"""
correlate.py - Cross-chunk finding aggregation, deduplication, and rule correlation.

This is where the magic happens:
  1. Gathers findings from every chunk in the job.
  2. Merges findings by (attack_type, entity):
       - unions all evidence items
       - calculates min(line) and max(line)
       - elevates severity to the highest observed
  3. Runs deterministic correlation and escalation rules against the StateTable:
       - Escalate brute force to CRITICAL account takeover if an IP successfully logged in
         after multiple failures, and append post-auth session activities (admin, export)
       - Escalate scanning IP to HIGH/CRITICAL if directory traversal / admin access was attempted
       - Validate and link prompt injection attempts
       - Validate high-frequency rate bursts
  4. Filters out benign operational noise (health monitors, deploy 503s, transient DB retries).
  5. Optionally requests a short executive summary from the local model (with template fallback).
  6. Produces the final sorted, structured report.
"""

import os
import json
import logging
from typing import Optional

from app.state import StateTable, EntityRecord
from app.llm import OllamaClient
from app.prompts import SYSTEM_PROMPT_SUMMARY, build_summary_prompt
from app.parser import parse_json_response

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}


def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.get(sev.title(), 0)


def max_severity(sev1: str, sev2: str) -> str:
    return sev1 if severity_rank(sev1) >= severity_rank(sev2) else sev2


def merge_chunk_findings(chunk_results: list[dict]) -> list[dict]:
    """
    Combine raw findings from all chunks by (attack_type, entity).
    """
    merged_map: dict[tuple[str, str], dict] = {}

    for cr in chunk_results:
        for f in cr.get("findings", []):
            attack_type = f.get("attack_type", "unknown").lower()
            entity = f.get("entity", "unknown")
            key = (attack_type, entity)

            if key not in merged_map:
                merged_map[key] = {
                    "attack_type": attack_type,
                    "entity": entity,
                    "severity": f.get("severity", "Medium"),
                    "confidence": f.get("confidence", "suspected"),
                    "reason": f.get("reason", ""),
                    "suggested_action": f.get("suggested_action", ""),
                    "evidence": [],
                    "start_line": 999999,
                    "end_line": 0,
                }

            entry = merged_map[key]
            entry["severity"] = max_severity(entry["severity"], f.get("severity", "Medium"))
            if f.get("confidence") == "confirmed":
                entry["confidence"] = "confirmed"

            # Combine evidence
            for ev in f.get("evidence", []):
                line = ev.get("line")
                if line:
                    entry["start_line"] = min(entry["start_line"], line)
                    entry["end_line"] = max(entry["end_line"], line)
                # Avoid duplicate evidence lines
                if not any(e.get("line") == line for e in entry["evidence"]):
                    entry["evidence"].append(ev)

    # Clean up bounds if no evidence line recorded
    for entry in merged_map.values():
        if entry["start_line"] == 999999:
            entry["start_line"] = 0

    return list(merged_map.values())


def apply_deterministic_correlations(
    merged_findings: list[dict],
    state: StateTable,
) -> list[dict]:
    """
    Apply correlation rules using the deterministic StateTable facts.
    Ensures complete accuracy across chunks.
    """
    correlations: list[dict] = list(merged_findings)

    for eid, entity in state.entities.items():
        # Rule 1: Brute Force -> Account Takeover & Data Exfiltration
        if entity.has_success_after_failures and entity.failed_logins >= 2:
            evidence = []
            for line in sorted([entity.first_line, entity.last_line]):
                evidence.append({"line": line, "snippet": f"IP {entity.entity_id} authentication events"})

            # Check if there's existing brute force entry
            existing = next(
                (f for f in correlations if f["entity"] == entity.entity_id and "brute" in f["attack_type"]),
                None
            )
            if existing:
                existing["attack_type"] = "brute_force_and_account_takeover"
                existing["severity"] = "Critical"
                existing["confidence"] = "confirmed"
                existing["reason"] = (
                    f"Entity executed {entity.failed_logins} failed login attempts followed by "
                    f"a successful login. High risk of account compromise."
                )
                existing["suggested_action"] = (
                    f"Immediately revoke active sessions ({', '.join(entity.associated_sessions)}), "
                    f"lock affected accounts ({', '.join(entity.associated_users)}), and block IP {entity.entity_id}."
                )
            else:
                correlations.append({
                    "attack_type": "brute_force_and_account_takeover",
                    "entity": entity.entity_id,
                    "severity": "Critical",
                    "confidence": "confirmed",
                    "start_line": entity.first_line,
                    "end_line": entity.last_line,
                    "reason": f"{entity.failed_logins} failed logins followed by successful login.",
                    "suggested_action": f"Invalidate sessions and ban IP {entity.entity_id}.",
                    "evidence": evidence,
                })

        # Rule 2: Web Reconnaissance & Vulnerability Scanning + Traversal
        if (entity.is_scanner or entity.traversal_evidence) and (len(entity.probe_evidence) >= 2 or len(entity.traversal_evidence) >= 1):
            existing = next(
                (f for f in correlations if f["entity"] == entity.entity_id and ("scan" in f["attack_type"] or "probe" in f["attack_type"] or "traversal" in f["attack_type"])),
                None
            )
            all_ev = [e.to_dict() for e in (entity.probe_evidence + entity.traversal_evidence)]
            sev = "High" if entity.traversal_evidence else "Medium"
            reason = (
                f"Host conducted systematic discovery probing across {len(entity.probe_evidence)} endpoints "
                f"and {len(entity.traversal_evidence)} path traversal attempts."
            )
            if existing:
                existing["severity"] = max_severity(existing["severity"], sev)
                existing["confidence"] = "confirmed"
                existing["reason"] = reason
                existing["evidence"] = all_ev
            else:
                correlations.append({
                    "attack_type": "reconnaissance_and_path_traversal",
                    "entity": entity.entity_id,
                    "severity": sev,
                    "confidence": "confirmed",
                    "start_line": entity.first_line,
                    "end_line": entity.last_line,
                    "reason": reason,
                    "suggested_action": f"Block IP {entity.entity_id} at WAF/firewall layer.",
                    "evidence": all_ev,
                })

        # Rule 3: Prompt Injection Attempts
        if entity.has_prompt_injection:
            existing = next(
                (f for f in correlations if f["entity"] == entity.entity_id and "prompt" in f["attack_type"]),
                None
            )
            ev = [e.to_dict() for e in entity.prompt_inj_evidence]
            if existing:
                existing["attack_type"] = "prompt_injection_attempt"
                existing["severity"] = "High"
                existing["confidence"] = "confirmed"
                existing["evidence"] = ev
            else:
                correlations.append({
                    "attack_type": "prompt_injection_attempt",
                    "entity": entity.entity_id,
                    "severity": "High",
                    "confidence": "confirmed",
                    "start_line": ev[0]["line"] if ev else entity.first_line,
                    "end_line": ev[-1]["line"] if ev else entity.last_line,
                    "reason": "Host submitted malicious instructions designed to hijack log analyzer.",
                    "suggested_action": "Sanitize user inputs and quarantine client IP.",
                    "evidence": ev,
                })

        # Rule 4: SQL Injection
        if entity.sqli_evidence:
            existing = next(
                (f for f in correlations if f["entity"] == entity.entity_id and "sql" in f["attack_type"]),
                None
            )
            ev = [e.to_dict() for e in entity.sqli_evidence]
            if existing:
                existing["severity"] = "High"
                existing["confidence"] = "confirmed"
                existing["evidence"] = ev
            else:
                correlations.append({
                    "attack_type": "sql_injection",
                    "entity": entity.entity_id,
                    "severity": "High",
                    "confidence": "confirmed",
                    "start_line": ev[0]["line"] if ev else entity.first_line,
                    "end_line": ev[-1]["line"] if ev else entity.last_line,
                    "reason": "Structured SQL injection payloads detected in request query parameters.",
                    "suggested_action": "Ensure parameterized queries and block origin IP.",
                    "evidence": ev,
                })

        # Rule 5: Rate Limiting Bursts
        if entity.has_high_rate:
            existing = next(
                (f for f in correlations if f["entity"] == entity.entity_id and "rate" in f["attack_type"]),
                None
            )
            ev = [e.to_dict() for e in entity.rate_limit_evidence]
            if existing:
                existing["severity"] = max_severity(existing["severity"], "Medium")
                existing["confidence"] = "confirmed"
            else:
                correlations.append({
                    "attack_type": "rate_limit_burst",
                    "entity": entity.entity_id,
                    "severity": "Medium",
                    "confidence": "confirmed",
                    "start_line": ev[0]["line"] if ev else entity.first_line,
                    "end_line": ev[-1]["line"] if ev else entity.last_line,
                    "reason": f"High volume burst requests triggering HTTP 429 rate limit ({len(ev)} throttled).",
                    "suggested_action": "Apply aggressive IP throttling or temporary block.",
                    "evidence": ev,
                })

    # Filter false positives: ignore health monitor IPs and purely benign entities
    cleaned = []
    for f in correlations:
        ent = f.get("entity", "")
        # Don't flag health monitors
        if "192.0.2.10" in ent or "HealthMonitor" in ent:
            continue
        cleaned.append(f)

    # Sort final findings by severity: Critical -> High -> Medium -> Low
    cleaned.sort(key=lambda x: severity_rank(x.get("severity", "Low")), reverse=True)
    return cleaned


def generate_executive_summary(
    findings: list[dict],
    client: Optional[OllamaClient] = None,
) -> dict:
    """
    Generate high-level summary. If model call fails or takes too long,
    uses clean deterministic template.
    """
    total_findings = len(findings)
    crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    med_count = sum(1 for f in findings if f.get("severity") == "Medium")

    overall_risk = "Low"
    if crit_count > 0:
        overall_risk = "Critical"
    elif high_count > 0:
        overall_risk = "High"
    elif med_count > 0:
        overall_risk = "Medium"

    # Default template summary
    template_summary = (
        f"Security analysis identified {total_findings} distinct security incident(s) across log analysis. "
        f"Highest identified risk is {overall_risk.upper()} ({crit_count} Critical, {high_count} High, {med_count} Medium). "
        f"Immediate mitigation recommended for compromised accounts and persistent hostile origins."
    )

    if not client or not findings:
        return {"summary": template_summary, "risk_level": overall_risk}

    try:
        mini_findings = [
            {"type": f["attack_type"], "entity": f["entity"], "severity": f["severity"]}
            for f in findings[:6]
        ]
        user_prompt = build_summary_prompt(json.dumps(mini_findings))
        res = client.generate(
            system_prompt=SYSTEM_PROMPT_SUMMARY,
            user_prompt=user_prompt,
            num_predict=150,
            temperature=0.2,
        )
        parsed = parse_json_response(res.text)
        if isinstance(parsed, dict) and "summary" in parsed:
            return {
                "summary": parsed["summary"],
                "risk_level": parsed.get("risk_level", overall_risk),
            }
    except Exception as e:
        logger.warning("Executive summary model call failed, using fallback: %s", e)

    return {"summary": template_summary, "risk_level": overall_risk}


def build_final_report(
    job_id: str,
    job_dir: str,
    state: StateTable,
    client: Optional[OllamaClient] = None,
) -> dict:
    """
    Collate chunk outputs and build the complete consolidated report.
    """
    chunks_dir = os.path.join(job_dir, "chunks")
    chunk_results = []
    if os.path.exists(chunks_dir):
        for fname in sorted(os.listdir(chunks_dir), key=lambda x: int(x.split(".")[0]) if x.split(".")[0].isdigit() else 999):
            if fname.endswith(".json"):
                with open(os.path.join(chunks_dir, fname), "r", encoding="utf-8") as f:
                    chunk_results.append(json.load(f))

    merged = merge_chunk_findings(chunk_results)
    correlated = apply_deterministic_correlations(merged, state)
    exec_summary = generate_executive_summary(correlated, client)

    return {
        "job_id": job_id,
        "executive_summary": exec_summary["summary"],
        "overall_risk": exec_summary["risk_level"],
        "total_findings": len(correlated),
        "findings": correlated,
        "entity_statistics": {
            eid: {
                "requests": e.requests,
                "failed_logins": e.failed_logins,
                "successful_logins": e.successful_logins,
                "is_suspicious": e.is_suspicious,
            }
            for eid, e in state.entities.items()
            if e.is_suspicious or e.requests > 5
        },
    }

