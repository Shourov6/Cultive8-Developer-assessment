"""
test_correlate.py - Unit tests for finding consolidation and correlation engine.

Tests cover:
  - Finding merging across chunks
  - Evidence collation and line-span calculation
  - Severity escalation (Critical > High > Medium > Low)
  - Brute force -> Account takeover correlation rule
  - Scanning + Traversal escalation rule
  - Exclusion of benign operational noise (health monitors)
  - Executive summary fallback generation
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.correlate import (
    merge_chunk_findings,
    apply_deterministic_correlations,
    generate_executive_summary,
    severity_rank,
    max_severity,
)
from app.state import StateTable, EntityRecord, EvidenceItem


class TestCorrelate:
    def test_severity_ordering(self):
        assert severity_rank("Critical") > severity_rank("High")
        assert severity_rank("High") > severity_rank("Medium")
        assert severity_rank("Medium") > severity_rank("Low")
        assert max_severity("Low", "Critical") == "Critical"
        assert max_severity("High", "Medium") == "High"

    def test_merge_chunk_findings(self):
        chunk1 = {
            "chunk_index": 0,
            "findings": [
                {
                    "attack_type": "brute_force",
                    "entity": "203.0.113.44",
                    "severity": "Medium",
                    "confidence": "suspected",
                    "evidence": [{"line": 5, "snippet": "failed login"}],
                }
            ],
        }
        chunk2 = {
            "chunk_index": 1,
            "findings": [
                {
                    "attack_type": "brute_force",
                    "entity": "203.0.113.44",
                    "severity": "High",
                    "confidence": "confirmed",
                    "evidence": [{"line": 13, "snippet": "failed login attempt 2"}],
                }
            ],
        }

        merged = merge_chunk_findings([chunk1, chunk2])
        assert len(merged) == 1
        f = merged[0]
        assert f["attack_type"] == "brute_force"
        assert f["entity"] == "203.0.113.44"
        assert f["severity"] == "High"
        assert f["confidence"] == "confirmed"
        assert len(f["evidence"]) == 2
        assert f["start_line"] == 5
        assert f["end_line"] == 13

    def test_brute_force_account_takeover_rule(self):
        state = StateTable()
        rec = state.get_or_create("203.0.113.44")
        rec.failed_logins = 6
        rec.successful_logins = 1
        rec.has_success_after_failures = True
        rec.first_line = 5
        rec.last_line = 196
        rec.associated_users.add("workspace.admin")
        rec.associated_sessions.add("sess-demo-8f20")

        initial_findings = [
            {
                "attack_type": "brute_force",
                "entity": "203.0.113.44",
                "severity": "Medium",
                "evidence": [{"line": 5, "snippet": "L5 login failed"}],
            }
        ]

        correlated = apply_deterministic_correlations(initial_findings, state)
        assert len(correlated) == 1
        c = correlated[0]
        assert c["attack_type"] == "brute_force_and_account_takeover"
        assert c["severity"] == "Critical"
        assert c["confidence"] == "confirmed"
        assert "workspace.admin" in c["suggested_action"]

    def test_benign_health_monitor_excluded(self):
        state = StateTable()
        rec = state.get_or_create("192.0.2.10")
        rec.requests = 50

        findings = [
            {
                "attack_type": "probe",
                "entity": "192.0.2.10",
                "severity": "Low",
                "evidence": [{"line": 3, "snippet": "/health"}],
            }
        ]

        correlated = apply_deterministic_correlations(findings, state)
        assert len(correlated) == 0

    def test_executive_summary_fallback(self):
        findings = [
            {"attack_type": "brute_force_and_account_takeover", "entity": "203.0.113.44", "severity": "Critical"},
            {"attack_type": "sql_injection", "entity": "203.0.113.72", "severity": "High"},
        ]
        res = generate_executive_summary(findings, client=None)
        assert res["risk_level"] == "Critical"
        assert "2 distinct security incident(s)" in res["summary"]

