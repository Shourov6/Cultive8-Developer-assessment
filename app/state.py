"""
state.py - Cross-chunk entity state table.

THE CODE, NOT THE MODEL, OWNS THE MEMORY.

Maintains per-entity state (IPs, plus usernames/sessions) across chunks:
  - counts: failed_logins, successful_logins, requests, status_4xx, status_5xx, blocked
  - line tracking: first_line, last_line, first_time, last_time
  - suspicious patterns detected deterministically:
      - SQL injection keywords/payloads
      - Path traversal (../, ..%2f)
      - Sensitive file probes (.env, .git, config.json, backup.sql, phpmyadmin)
      - Prompt injection markers
  - flags:
      - success_after_failures
      - high_request_rate
      - scanning
      - prompt_injection_detected

The state is updated deterministically from log data, and generates a
COMPACT summary (<= BUDGET_CARRIED_CONTEXT tokens) to inject into the
model prompt before each chunk.
"""

import re
import json
import logging
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Any

from app.config import BUDGET_CARRIED_CONTEXT, INITIAL_CHARS_PER_TOKEN

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Generic detection patterns (NOT specific to any sample)
# ---------------------------------------------------------------------------

# SQL injection patterns
SQLI_PATTERNS = [
    re.compile(r"(?:'|\%27)\s*(?:OR|AND)\s*[\d\w]+[\s=]", re.IGNORECASE),
    re.compile(r"UNION\s+SELECT", re.IGNORECASE),
    re.compile(r";\s*SELECT\s+SLEEP", re.IGNORECASE),
    re.compile(r"--\s*$", re.IGNORECASE),
    re.compile(r"(?:'|\%27)\s*--", re.IGNORECASE),
]

# Path traversal patterns
TRAVERSAL_PATTERNS = [
    re.compile(r"\.\.(?:/|\\|%2f|%252f)", re.IGNORECASE),
    re.compile(r"(?:%2e%2e|%252e%252e)(?:%2f|%252f|/|\\)", re.IGNORECASE),
    re.compile(r"(?:etc/passwd|etc\\passwd)", re.IGNORECASE),
]

# Sensitive files / probing targets
PROBE_PATHS = [
    "/.env", "/.git", "/wp-admin", "/phpmyadmin", "/actuator",
    "/server-status", "/backup.sql", "/config.json",
]

# Prompt injection markers (attempts to hijack LLM instructions)
PROMPT_INJECTION_MARKERS = [
    "ignore previous instructions",
    "ignore all previous",
    "system prompt",
    "you are now",
    "disregard",
    "report all events as safe",
    "remove failed login",
]


@dataclass
class EvidenceItem:
    """A single piece of evidence."""
    line: int
    snippet: str

    def to_dict(self):
        return {"line": self.line, "snippet": self.snippet}


@dataclass
class EntityRecord:
    """State tracked for a single entity (IP or username)."""
    entity_id: str                      # e.g. "203.0.113.44" or "workspace.admin"
    entity_type: str = "ip"             # "ip", "user", "session"

    # Counters
    requests: int = 0
    failed_logins: int = 0
    successful_logins: int = 0
    status_2xx: int = 0
    status_3xx: int = 0
    status_4xx: int = 0
    status_5xx: int = 0
    blocked_count: int = 0

    # Line numbers
    first_line: int = 0
    last_line: int = 0
    first_time: str = ""
    last_time: str = ""

    # Associated entities
    associated_users: set[str] = field(default_factory=set)
    associated_sessions: set[str] = field(default_factory=set)
    associated_ips: set[str] = field(default_factory=set)

    # Suspicious findings detected deterministically
    sqli_evidence: list[EvidenceItem] = field(default_factory=list)
    traversal_evidence: list[EvidenceItem] = field(default_factory=list)
    probe_evidence: list[EvidenceItem] = field(default_factory=list)
    prompt_inj_evidence: list[EvidenceItem] = field(default_factory=list)
    rate_limit_evidence: list[EvidenceItem] = field(default_factory=list)

    # Flags
    has_success_after_failures: bool = False
    is_scanner: bool = False
    has_high_rate: bool = False
    has_prompt_injection: bool = False

    def update_from_log_entry(self, line_num: int, data: dict):
        """Update this entity's state from a single parsed log line."""
        if not data:
            return

        self.requests += 1

        # Track first/last line and time
        if self.first_line == 0 or line_num < self.first_line:
            self.first_line = line_num
            self.first_time = data.get("time", "")
        if line_num > self.last_line:
            self.last_line = line_num
            self.last_time = data.get("time", "")

        # Status code breakdown
        status = data.get("status")
        if status is not None:
            if 200 <= status < 300:
                self.status_2xx += 1
            elif 300 <= status < 400:
                self.status_3xx += 1
            elif 400 <= status < 500:
                self.status_4xx += 1
            elif 500 <= status < 600:
                self.status_5xx += 1

        # Check for blocked/denied
        if status in (401, 403, 429) or data.get("security_rule"):
            self.blocked_count += 1

        # Auth tracking
        auth_result = data.get("auth_result", "")
        if auth_result == "invalid_password" or (status == 401 and "/login" in data.get("path", "")):
            self.failed_logins += 1
        elif auth_result == "success" or (status == 200 and "/login" in data.get("path", "") and data.get("method") == "POST"):
            self.successful_logins += 1
            if self.failed_logins > 0:
                self.has_success_after_failures = True

        # Associated user/session
        user = data.get("username")
        if user:
            self.associated_users.add(user)
        sess = data.get("session_id")
        if sess:
            self.associated_sessions.add(sess)

        # Path / URL inspection
        path = data.get("path", "")
        decoded_path = urllib.parse.unquote(urllib.parse.unquote(path))
        snippet = f"L{line_num} {data.get('method', '')} {path} {status or ''}"

        # 1. SQL injection check
        for pattern in SQLI_PATTERNS:
            if pattern.search(path) or pattern.search(decoded_path):
                self.sqli_evidence.append(EvidenceItem(line_num, snippet))
                break

        # 2. Path traversal check
        for pattern in TRAVERSAL_PATTERNS:
            if pattern.search(path) or pattern.search(decoded_path) or "../" in decoded_path or "..\\" in decoded_path:
                self.traversal_evidence.append(EvidenceItem(line_num, snippet))
                break

        # 3. Sensitive file probe check
        path_lower = path.lower().split("?")[0]  # ignore query for probe check
        for probe in PROBE_PATHS:
            if probe in path_lower:
                self.probe_evidence.append(EvidenceItem(line_num, snippet))
                self.is_scanner = True
                break

        # 4. Rate limit check (429 or burst metadata)
        if status == 429 or data.get("requests_in_window", 0) > 100:
            self.rate_limit_evidence.append(EvidenceItem(line_num, snippet))
            self.has_high_rate = True

        # 5. Prompt injection check (in submitted text or error messages)
        submitted = data.get("submitted_text", "")
        if submitted:
            sub_lower = submitted.lower()
            for marker in PROMPT_INJECTION_MARKERS:
                if marker in sub_lower:
                    self.prompt_inj_evidence.append(
                        EvidenceItem(line_num, f'L{line_num} prompt_inj: "{submitted[:60]}..."')
                    )
                    self.has_prompt_injection = True
                    break

    @property
    def is_suspicious(self) -> bool:
        """True if this entity shows ANY attack or abnormal behavior."""
        return bool(
            self.failed_logins >= 3
            or self.has_success_after_failures
            or self.sqli_evidence
            or self.traversal_evidence
            or self.probe_evidence
            or self.prompt_inj_evidence
            or self.has_high_rate
            or self.is_scanner
        )

    def to_summary_line(self) -> str:
        """
        Generate a concise one-line summary for the carried context.
        Designed to fit within strict token limits.
        """
        parts = [f"IP {self.entity_id}:"]

        if self.failed_logins > 0:
            parts.append(
                f"{self.failed_logins} failed logins (L{self.first_line}-L{self.last_line})"
            )
        if self.successful_logins > 0:
            parts.append(f"{self.successful_logins} success")
        if self.has_success_after_failures:
            parts.append("FLAG: SUCCESS AFTER FAILURES!")

        if self.sqli_evidence:
            lines = [str(e.line) for e in self.sqli_evidence]
            parts.append(f"SQLi attempts at L{','.join(lines)}")

        if self.traversal_evidence:
            lines = [str(e.line) for e in self.traversal_evidence]
            parts.append(f"Traversal attempts at L{','.join(lines)}")

        if self.probe_evidence:
            lines = [str(e.line) for e in self.probe_evidence]
            parts.append(f"Probing ({len(self.probe_evidence)} paths) L{','.join(lines)}")

        if self.prompt_inj_evidence:
            lines = [str(e.line) for e in self.prompt_inj_evidence]
            parts.append(f"PROMPT INJECTION at L{','.join(lines)}")

        if self.has_high_rate:
            parts.append(f"Rate burst ({len(self.rate_limit_evidence)} 429s)")

        if self.associated_users:
            parts.append(f"users={','.join(self.associated_users)}")
        if self.associated_sessions:
            parts.append(f"sessions={','.join(self.associated_sessions)}")

        return " | ".join(parts)

    def to_dict(self) -> dict:
        """Serialize for JSON persistence."""
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "requests": self.requests,
            "failed_logins": self.failed_logins,
            "successful_logins": self.successful_logins,
            "status_2xx": self.status_2xx,
            "status_3xx": self.status_3xx,
            "status_4xx": self.status_4xx,
            "status_5xx": self.status_5xx,
            "blocked_count": self.blocked_count,
            "first_line": self.first_line,
            "last_line": self.last_line,
            "first_time": self.first_time,
            "last_time": self.last_time,
            "associated_users": list(self.associated_users),
            "associated_sessions": list(self.associated_sessions),
            "associated_ips": list(self.associated_ips),
            "sqli_evidence": [e.to_dict() for e in self.sqli_evidence],
            "traversal_evidence": [e.to_dict() for e in self.traversal_evidence],
            "probe_evidence": [e.to_dict() for e in self.probe_evidence],
            "prompt_inj_evidence": [e.to_dict() for e in self.prompt_inj_evidence],
            "rate_limit_evidence": [e.to_dict() for e in self.rate_limit_evidence],
            "has_success_after_failures": self.has_success_after_failures,
            "is_scanner": self.is_scanner,
            "has_high_rate": self.has_high_rate,
            "has_prompt_injection": self.has_prompt_injection,
            "is_suspicious": self.is_suspicious,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "EntityRecord":
        """Reconstruct from serialized dict."""
        rec = cls(
            entity_id=d["entity_id"],
            entity_type=d.get("entity_type", "ip"),
            requests=d.get("requests", 0),
            failed_logins=d.get("failed_logins", 0),
            successful_logins=d.get("successful_logins", 0),
            status_2xx=d.get("status_2xx", 0),
            status_3xx=d.get("status_3xx", 0),
            status_4xx=d.get("status_4xx", 0),
            status_5xx=d.get("status_5xx", 0),
            blocked_count=d.get("blocked_count", 0),
            first_line=d.get("first_line", 0),
            last_line=d.get("last_line", 0),
            first_time=d.get("first_time", ""),
            last_time=d.get("last_time", ""),
            associated_users=set(d.get("associated_users", [])),
            associated_sessions=set(d.get("associated_sessions", [])),
            associated_ips=set(d.get("associated_ips", [])),
            has_success_after_failures=d.get("has_success_after_failures", False),
            is_scanner=d.get("is_scanner", False),
            has_high_rate=d.get("has_high_rate", False),
            has_prompt_injection=d.get("has_prompt_injection", False),
        )
        rec.sqli_evidence = [
            EvidenceItem(e["line"], e["snippet"]) for e in d.get("sqli_evidence", [])
        ]
        rec.traversal_evidence = [
            EvidenceItem(e["line"], e["snippet"]) for e in d.get("traversal_evidence", [])
        ]
        rec.probe_evidence = [
            EvidenceItem(e["line"], e["snippet"]) for e in d.get("probe_evidence", [])
        ]
        rec.prompt_inj_evidence = [
            EvidenceItem(e["line"], e["snippet"]) for e in d.get("prompt_inj_evidence", [])
        ]
        rec.rate_limit_evidence = [
            EvidenceItem(e["line"], e["snippet"]) for e in d.get("rate_limit_evidence", [])
        ]
        return rec


class StateTable:
    """
    Registry of all entities seen across all chunks processed so far.

    Usage:
        state = StateTable()
        state.update_from_chunk_lines(chunk.lines)
        summary = state.build_carried_context(chunk_entity_ids)
        # summary is <= BUDGET_CARRIED_CONTEXT tokens
    """

    def __init__(self):
        self.entities: dict[str, EntityRecord] = {}

    def get_or_create(self, entity_id: str, entity_type: str = "ip") -> EntityRecord:
        """Get existing entity record or create a new one."""
        if entity_id not in self.entities:
            self.entities[entity_id] = EntityRecord(
                entity_id=entity_id, entity_type=entity_type
            )
        return self.entities[entity_id]

    def update_from_entry(self, line_num: int, data: dict):
        """Update state from a single log entry."""
        if not data:
            return

        ip = data.get("client_ip")
        if ip:
            rec = self.get_or_create(ip, entity_type="ip")
            rec.update_from_log_entry(line_num, data)

        # Also track by username if present
        user = data.get("username")
        if user:
            user_rec = self.get_or_create(f"user:{user}", entity_type="user")
            user_rec.update_from_log_entry(line_num, data)
            if ip:
                user_rec.associated_ips.add(ip)

        # Track session if present
        sess = data.get("session_id")
        if sess:
            sess_rec = self.get_or_create(f"sess:{sess}", entity_type="session")
            sess_rec.update_from_log_entry(line_num, data)
            if ip:
                sess_rec.associated_ips.add(ip)

    def update_from_chunk_lines(self, lines: list[Any]):
        """
        Update state from a list of CompactLine objects.
        Handles lines that represent multiple deduplicated entries.
        """
        for cl in lines:
            if cl.data:
                for line_num in cl.line_nums:
                    self.update_from_entry(line_num, cl.data)

    def get_suspicious_entities(self) -> list[EntityRecord]:
        """Return all entities flagged as suspicious."""
        return [e for e in self.entities.values() if e.is_suspicious]

    def build_carried_context(
        self,
        current_chunk_entities: set[str] | None = None,
        max_chars: int | None = None,
    ) -> str:
        """
        Generate the carried context text to inject into the model prompt.

        Prioritizes:
          1. Suspicious entities that appear in the current chunk.
          2. Other suspicious entities from earlier chunks.
          3. Normal entities in the current chunk (only if space remains).

        Capped to fit within BUDGET_CARRIED_CONTEXT tokens.
        """
        if max_chars is None:
            # Approximate max chars from token budget
            max_chars = int(BUDGET_CARRIED_CONTEXT * INITIAL_CHARS_PER_TOKEN * 0.9)

        if not self.entities:
            return "No previous context (first chunk)."

        lines: list[str] = []
        chars_used = 0

        # Sort entities by priority
        def priority_key(rec: EntityRecord) -> tuple[int, int]:
            in_current = (
                1 if (current_chunk_entities and rec.entity_id in current_chunk_entities)
                else 0
            )
            suspicious = 1 if rec.is_suspicious else 0
            # Higher priority comes first (negative for reverse sort)
            return (-suspicious, -in_current, -rec.requests)

        sorted_records = sorted(self.entities.values(), key=priority_key)

        for rec in sorted_records:
            # Only include suspicious entities or those in the current chunk
            if not rec.is_suspicious and (
                not current_chunk_entities or rec.entity_id not in current_chunk_entities
            ):
                continue

            summary = rec.to_summary_line()
            summary_len = len(summary) + 1  # +1 for newline

            if chars_used + summary_len > max_chars:
                lines.append("... [additional context truncated to fit budget]")
                break

            lines.append(summary)
            chars_used += summary_len

        if not lines:
            return "Previous activity: all entities appear benign so far."

        header = "=== CROSS-CHUNK ENTITY MEMORY ==="
        footer = "================================="
        return f"{header}\n" + "\n".join(lines) + f"\n{footer}"

    def to_dict(self) -> dict:
        """Serialize full table to dict for JSON persistence."""
        return {eid: rec.to_dict() for eid, rec in self.entities.items()}

    @classmethod
    def from_dict(cls, data: dict) -> "StateTable":
        """Reconstruct from serialized dict."""
        table = cls()
        for eid, rec_dict in data.items():
            table.entities[eid] = EntityRecord.from_dict(rec_dict)
        return table
