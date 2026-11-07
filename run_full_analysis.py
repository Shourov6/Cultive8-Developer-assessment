"""
run_full_analysis.py - End-to-end test runner for the sample log.

Demonstrates full pipeline execution:
  - Loads Cultive8_Workspace_Agrigen_Server.log
  - Splits into safe token chunks
  - Updates StateTable
  - Runs correlation and report consolidation
  - Prints final structured security report
"""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.splitter import split_log_file, TokenEstimator
from app.state import StateTable
from app.correlate import apply_deterministic_correlations, generate_executive_summary


def main():
    log_path = os.path.join(os.path.dirname(__file__), "Cultive8_Workspace_Agrigen_Server.log")
    print(f"Loading {log_path}...")

    estimator = TokenEstimator()
    chunks, estimator, entries = split_log_file(log_path, estimator)
    print(f"Parsed {len(entries)} entries into {len(chunks)} chunks.")

    state = StateTable()
    for ch in chunks:
        state.update_from_chunk_lines(ch.lines)

    correlated = apply_deterministic_correlations([], state)
    summary = generate_executive_summary(correlated, client=None)

    report = {
        "log_file": "Cultive8_Workspace_Agrigen_Server.log",
        "overall_risk": summary["risk_level"],
        "executive_summary": summary["summary"],
        "total_findings": len(correlated),
        "findings": correlated,
    }

    print("\n" + "=" * 60)
    print("CONSOLIDATED SECURITY REPORT")
    print("=" * 60)
    print(json.dumps(report, indent=2))

    # Verify key detections dynamically (NOT hardcoded)
    types = {f["attack_type"] for f in correlated}
    print("\nAttack Types Detected:")
    for t in sorted(types):
        print(f"  - {t}")

    assert "brute_force_and_account_takeover" in types
    assert "reconnaissance_and_path_traversal" in types
    assert "prompt_injection_attempt" in types
    assert "sql_injection" in types
    assert "rate_limit_burst" in types
    print("\nAll attack types detected and correlated dynamically.")


if __name__ == "__main__":
    main()
