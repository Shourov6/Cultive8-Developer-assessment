"""
splitter.py - Log line parser, compact formatter, deduplicator, and chunker.

This module handles the critical pipeline:
  raw log file → parsed entries → compact lines → deduplicated → chunks

Design decisions (all driven by the 2048-token context limit):

  1. COMPACT FORMAT: Each JSON log line is converted to a short string like:
       L58 08:02:30 203.0.113.44 POST /api/v1/auth/login 401 user=admin invalid_password
     This drops noise fields (request_id, response_bytes, long user agents)
     while preserving everything needed for security analysis.

  2. LINE NUMBERS: Always 1-based, matching the original file. Every compact
     line starts with L<n> so findings can reference exact lines.

  3. DEDUPLICATION: Lines with the same request_id or event_id are merged.
     The compact form notes "×N (L5,L6,L7)" for duplicates.

  4. CHUNKING: Compact lines are packed into chunks that fit within the
     BUDGET_LOG_CHUNK token limit. Never cuts a log entry in half. Uses a
     chars-per-token estimate (calibrated from real Ollama responses).

  5. NON-JSON FALLBACK: If a line isn't valid JSON, it's kept as raw text
     (truncated to 200 chars) with its line number.
"""

import json
import re
import logging
from dataclasses import dataclass, field
from typing import Generator

from app.config import (
    BUDGET_LOG_CHUNK,
    INITIAL_CHARS_PER_TOKEN,
    TOKEN_SAFETY_MARGIN,
)

logger = logging.getLogger(__name__)

# Maximum length for a raw (non-JSON) line before truncation
MAX_RAW_LINE_LENGTH = 200

# Patterns for deterministic benign pre-scan
_BENIGN_PROBE_WORDS = [
    ".env", ".git", "admin", "wp-", "phpmyadmin", "actuator", "backup", "config",
    "passwd", "union", "select", "sleep", "or 1=1", "ignore previous"
]


def is_chunk_provably_benign(chunk: "LogChunk") -> bool:
    """
    Returns True if every line in the chunk represents routine, benign traffic:
      - HTTP status is 200 or 304 (no 4xx/5xx errors)
      - No authentication attempts (no 401, no auth_result, no /login path)
      - No security rule violations
      - No SQL injection, traversal, probe keywords, or prompt injection
      - No rate-limiting indicators (no 429, requests_in_window <= 50)
    """
    if not chunk.lines:
        return True

    for cl in chunk.lines:
        data = cl.data
        if not data:
            # Raw unparsed text line: might be an error or stack trace, so inspect text
            txt_lower = cl.text.lower()
            if any(w in txt_lower for w in _BENIGN_PROBE_WORDS) or "error" in txt_lower:
                return False
            continue

        status = data.get("status")
        # Must be normal success or caching
        if status not in (200, 304):
            return False

        # Must not be an auth endpoint
        path = (data.get("path") or "").lower()
        if "/login" in path or "/auth" in path or data.get("auth_result"):
            return False

        # Must not have security flags
        if data.get("security_rule") or data.get("validation_error"):
            return False

        # Check for attack keywords in query or path
        if any(w in path for w in _BENIGN_PROBE_WORDS):
            return False

        # Check submitted text
        submitted = (data.get("submitted_text") or "").lower()
        if submitted and any(w in submitted for w in _BENIGN_PROBE_WORDS):
            return False

        # Check rate limit counters
        if data.get("requests_in_window", 0) > 50:
            return False

    return True


@dataclass
class ParsedEntry:
    """
    A single parsed log entry with original line number and extracted fields.
    """
    line_num: int          # 1-based line number in the original file
    raw_line: str          # original line text
    data: dict | None      # parsed JSON fields, or None if not JSON
    compact: str           # compact text representation for the model
    request_id: str = ""   # for deduplication
    event_id: str = ""     # for deduplication


@dataclass
class CompactLine:
    """
    A compact log line ready for chunking. May represent multiple
    deduplicated original lines.
    """
    line_nums: list[int]   # all original line numbers (1+ if deduplicated)
    text: str              # compact text for the model prompt
    data: dict | None      # parsed fields for state table updates
    char_count: int = 0    # cached len(text) for token estimation

    def __post_init__(self):
        self.char_count = len(self.text)


@dataclass
class LogChunk:
    """
    A group of compact lines that fits within the token budget.
    Sent as one prompt to the model.
    """
    chunk_index: int                     # 0-based chunk number
    lines: list[CompactLine]             # compact lines in this chunk
    start_line: int = 0                  # first original line number
    end_line: int = 0                    # last original line number
    estimated_tokens: int = 0            # estimated tokens for the text
    text: str = ""                       # joined compact lines (built by finalize)

    def finalize(self):
        """Build the joined text and compute metadata."""
        if self.lines:
            all_line_nums = []
            for cl in self.lines:
                all_line_nums.extend(cl.line_nums)
            self.start_line = min(all_line_nums)
            self.end_line = max(all_line_nums)
            self.text = "\n".join(cl.text for cl in self.lines)
        return self


# -----------------------------------------------------------------------
# User-Agent classifier
# -----------------------------------------------------------------------

def classify_user_agent(ua: str) -> str:
    """
    Convert a long user-agent string into a short label.
    Keeps security-relevant detail (tool type) while saving tokens.
    """
    if not ua:
        return ""
    ua_lower = ua.lower()

    if "curl" in ua_lower:
        return "curl"
    if "python-requests" in ua_lower:
        return "python-requests"
    if "go-http-client" in ua_lower:
        return "Go-http-client"
    if "aiohttp" in ua_lower:
        return "aiohttp"
    if "healthmonitor" in ua_lower or "health" in ua_lower:
        return "health-monitor"
    if "mozilla" in ua_lower or "chrome" in ua_lower or "safari" in ua_lower:
        return "browser"
    # Truncate unknown agents
    return ua[:30]


# -----------------------------------------------------------------------
# Compact formatter
# -----------------------------------------------------------------------

def format_compact(line_num: int, data: dict) -> str:
    """
    Convert a parsed JSON log entry into a compact one-line string.

    Format:
      L<num> <HH:MM:SS> <IP> <METHOD> <path> <status> [key=value ...]

    Drops: request_id, response_bytes, full user_agent (replaced with label),
           host (redundant with app).
    Keeps: app, service, level, message, username, auth_result, security_rule,
           exception, any security-relevant fields.
    """
    parts = [f"L{line_num}"]

    # Timestamp - extract just HH:MM:SS from ISO format
    time_str = data.get("time", "")
    if "T" in time_str:
        time_part = time_str.split("T")[1]
        # Remove trailing Z and milliseconds for brevity
        time_part = time_part.replace("Z", "").split(".")[0]
        parts.append(time_part)

    # App name (short, for context)
    app = data.get("app", "")
    if app:
        parts.append(f"[{app}]")

    # Service
    service = data.get("service", "")
    if service and service != "gateway":
        parts.append(f"svc={service}")

    # Level (only if not INFO — saves tokens for the common case)
    level = data.get("level", "")
    if level and level != "INFO":
        parts.append(level)

    # Client IP
    client_ip = data.get("client_ip", "")
    if client_ip:
        parts.append(client_ip)

    # HTTP method + path
    method = data.get("method", "")
    path = data.get("path", "")
    if method:
        parts.append(f"{method} {path}")
    elif path:
        parts.append(path)

    # Status code
    status = data.get("status")
    if status is not None:
        parts.append(str(status))

    # Duration (only if notably slow, > 1000ms)
    duration = data.get("duration_ms")
    if duration is not None and duration > 1000:
        parts.append(f"{duration}ms")

    # User agent (short label)
    ua = data.get("user_agent", "")
    if ua:
        ua_label = classify_user_agent(ua)
        if ua_label and ua_label not in ("browser", "health-monitor"):
            # Only include non-browser UA labels (browsers are normal)
            parts.append(f"ua={ua_label}")

    # --- Security-relevant fields ---
    username = data.get("username", "")
    if username:
        parts.append(f"user={username}")

    auth_result = data.get("auth_result", "")
    if auth_result:
        parts.append(auth_result)

    session_id = data.get("session_id", "")
    if session_id:
        parts.append(f"sess={session_id}")

    security_rule = data.get("security_rule", "")
    if security_rule:
        parts.append(f"rule={security_rule}")

    # Message (for non-HTTP log entries like errors, warnings)
    message = data.get("message", "")
    if message:
        # Truncate long messages
        if len(message) > 80:
            message = message[:77] + "..."
        parts.append(f'msg="{message}"')

    # Exception type
    exception = data.get("exception", "")
    if exception:
        parts.append(f"exc={exception}")

    # Extra fields for specific events
    for extra_key in [
        "procedure", "upstream", "http_status", "retry_in_seconds",
        "release", "maintenance_until", "healthy_instances",
        "items_processed", "items_failed", "submitted_text",
        "validation_error", "requests_in_window", "window_seconds",
        "backup_id", "task_id",
    ]:
        val = data.get(extra_key)
        if val is not None:
            val_str = str(val)
            if len(val_str) > 80:
                val_str = val_str[:77] + "..."
            parts.append(f"{extra_key}={val_str}")

    return " ".join(parts)


def parse_line(line_num: int, raw_line: str) -> ParsedEntry:
    """
    Parse a single line from the log file.

    - If it's valid JSON, extract fields and build compact form.
    - If not JSON, use the raw text (truncated) with the line number.
    """
    stripped = raw_line.strip()
    if not stripped:
        # Empty line — keep it minimal
        return ParsedEntry(
            line_num=line_num,
            raw_line=raw_line,
            data=None,
            compact=f"L{line_num} (empty)",
        )

    # Try JSON parse
    try:
        data = json.loads(stripped)
        if isinstance(data, dict):
            compact = format_compact(line_num, data)
            return ParsedEntry(
                line_num=line_num,
                raw_line=raw_line,
                data=data,
                compact=compact,
                request_id=data.get("request_id", ""),
                event_id=data.get("event_id", ""),
            )
    except (json.JSONDecodeError, ValueError):
        pass

    # Non-JSON fallback: use raw line (truncated)
    if len(stripped) > MAX_RAW_LINE_LENGTH:
        compact = f"L{line_num} {stripped[:MAX_RAW_LINE_LENGTH]}..."
    else:
        compact = f"L{line_num} {stripped}"

    return ParsedEntry(
        line_num=line_num,
        raw_line=raw_line,
        data=None,
        compact=compact,
    )


# -----------------------------------------------------------------------
# Line-by-line reader (avoids loading entire file into memory)
# -----------------------------------------------------------------------

def read_entries(file_path: str) -> Generator[ParsedEntry, None, None]:
    """
    Read a log file line by line, yielding ParsedEntry objects.

    - 1-based line numbering.
    - Handles encoding errors gracefully (replace mode).
    - For non-JSON logs, keeps indented continuation lines with their parent
      (e.g., stack traces). Since our sample is JSON-lines, this mainly
      matters for robustness with other log formats.
    """
    pending_parent: ParsedEntry | None = None

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line_num_0based, raw_line in enumerate(f):
            line_num = line_num_0based + 1  # 1-based
            stripped = raw_line.rstrip("\n\r")

            # Check if this is a continuation line (indented, not JSON)
            is_continuation = (
                stripped
                and (stripped[0] in (" ", "\t"))
                and not stripped.lstrip().startswith("{")
            )

            if is_continuation and pending_parent is not None:
                # Append to parent's compact form
                trunc = stripped.strip()[:100]
                pending_parent.compact += f"\n  {trunc}"
                # Don't yield separately — it's part of the parent
                continue

            # Yield any pending parent before starting a new entry
            if pending_parent is not None:
                yield pending_parent

            entry = parse_line(line_num, stripped)
            pending_parent = entry

    # Don't forget the last entry
    if pending_parent is not None:
        yield pending_parent


# -----------------------------------------------------------------------
# Deduplication
# -----------------------------------------------------------------------

def deduplicate(entries: list[ParsedEntry]) -> list[CompactLine]:
    """
    Merge entries with the same request_id or event_id.

    For duplicates, the compact text notes the count and all line numbers:
      L29 08:28:40 ... (×2 L29,L223)
    """
    # Group by dedup key (request_id or event_id, whichever is set)
    groups: dict[str, list[ParsedEntry]] = {}
    no_key: list[ParsedEntry] = []

    for entry in entries:
        key = entry.event_id or entry.request_id
        if key:
            groups.setdefault(key, []).append(entry)
        else:
            no_key.append(entry)

    result: list[CompactLine] = []

    for key, group in groups.items():
        if len(group) == 1:
            e = group[0]
            result.append(CompactLine(
                line_nums=[e.line_num],
                text=e.compact,
                data=e.data,
            ))
        else:
            # Merge duplicates
            first = group[0]
            all_nums = [e.line_num for e in group]
            nums_str = ",".join(f"L{n}" for n in all_nums)
            merged_text = f"{first.compact} (×{len(group)} {nums_str})"
            result.append(CompactLine(
                line_nums=all_nums,
                text=merged_text,
                data=first.data,
            ))

    # Add entries with no dedup key
    for entry in no_key:
        result.append(CompactLine(
            line_nums=[entry.line_num],
            text=entry.compact,
            data=entry.data,
        ))

    # Sort by first line number to maintain chronological order
    result.sort(key=lambda cl: cl.line_nums[0])

    logger.info(
        "Deduplication: %d entries → %d compact lines",
        len(entries), len(result),
    )
    return result


# -----------------------------------------------------------------------
# Token estimation
# -----------------------------------------------------------------------

class TokenEstimator:
    """
    Estimates token counts from character counts using a chars-per-token ratio.

    Starts with a conservative default and can be calibrated from real
    Ollama prompt_eval_count values.
    """

    def __init__(self, initial_cpt: float = INITIAL_CHARS_PER_TOKEN):
        self.chars_per_token = initial_cpt
        self._samples: list[tuple[int, int]] = []  # (chars, tokens) pairs

    def estimate_tokens(self, text: str) -> int:
        """Estimate how many tokens a text will consume."""
        if not text:
            return 0
        return int(len(text) / self.chars_per_token) + 1

    def estimate_tokens_safe(self, text: str) -> int:
        """Estimate with safety margin applied."""
        raw = self.estimate_tokens(text)
        # The safety margin means we treat the budget as smaller,
        # so we return the raw estimate (caller applies margin to budget)
        return raw

    def calibrate(self, char_count: int, actual_tokens: int):
        """
        Update the ratio based on a real Ollama response.
        Uses a weighted moving average to stay stable.
        """
        if actual_tokens <= 0 or char_count <= 0:
            return

        new_cpt = char_count / actual_tokens
        self._samples.append((char_count, actual_tokens))

        # Weighted average: recent samples matter more
        if len(self._samples) <= 1:
            self.chars_per_token = new_cpt
        else:
            # Simple exponential moving average
            alpha = 0.3  # weight for new sample
            self.chars_per_token = (
                alpha * new_cpt + (1 - alpha) * self.chars_per_token
            )

        logger.info(
            "Token estimator calibrated: %d chars / %d tokens = %.2f cpt "
            "(running avg: %.2f)",
            char_count, actual_tokens, new_cpt, self.chars_per_token,
        )

    @property
    def max_chars_for_budget(self) -> int:
        """
        Max characters of log text that fit in BUDGET_LOG_CHUNK tokens
        with safety margin applied.
        """
        safe_tokens = int(BUDGET_LOG_CHUNK * TOKEN_SAFETY_MARGIN)
        return int(safe_tokens * self.chars_per_token)


# -----------------------------------------------------------------------
# Chunker
# -----------------------------------------------------------------------

def chunk_lines(
    compact_lines: list[CompactLine],
    estimator: TokenEstimator,
) -> list[LogChunk]:
    """
    Pack compact lines into chunks that fit the token budget.

    Rules:
      - Never split a single CompactLine across chunks.
      - Each chunk's total text must fit within the safe token budget.
      - Chunks maintain chronological order.
    """
    max_chars = estimator.max_chars_for_budget
    logger.info(
        "Chunking %d lines, max %d chars/chunk (%.0f safe tokens, %.2f cpt)",
        len(compact_lines), max_chars,
        BUDGET_LOG_CHUNK * TOKEN_SAFETY_MARGIN,
        estimator.chars_per_token,
    )

    chunks: list[LogChunk] = []
    current_lines: list[CompactLine] = []
    current_chars = 0
    chunk_index = 0

    for cl in compact_lines:
        line_chars = cl.char_count + 1  # +1 for the newline separator

        # If this single line exceeds the budget, it goes in its own chunk
        # (the model will get a truncated view, but we don't lose it)
        if line_chars > max_chars:
            # Flush current chunk if any
            if current_lines:
                chunk = LogChunk(chunk_index=chunk_index, lines=current_lines)
                chunk.estimated_tokens = estimator.estimate_tokens(
                    "\n".join(l.text for l in current_lines)
                )
                chunk.finalize()
                chunks.append(chunk)
                chunk_index += 1
                current_lines = []
                current_chars = 0

            # Put the oversized line in its own chunk
            chunk = LogChunk(chunk_index=chunk_index, lines=[cl])
            chunk.estimated_tokens = estimator.estimate_tokens(cl.text)
            chunk.finalize()
            chunks.append(chunk)
            chunk_index += 1
            logger.warning(
                "Line L%d exceeds chunk budget (%d chars > %d max)",
                cl.line_nums[0], line_chars, max_chars,
            )
            continue

        # Would adding this line exceed the budget?
        if current_chars + line_chars > max_chars and current_lines:
            # Flush current chunk
            chunk = LogChunk(chunk_index=chunk_index, lines=current_lines)
            chunk.estimated_tokens = estimator.estimate_tokens(
                "\n".join(l.text for l in current_lines)
            )
            chunk.finalize()
            chunks.append(chunk)
            chunk_index += 1
            current_lines = []
            current_chars = 0

        current_lines.append(cl)
        current_chars += line_chars

    # Flush remaining lines
    if current_lines:
        chunk = LogChunk(chunk_index=chunk_index, lines=current_lines)
        chunk.estimated_tokens = estimator.estimate_tokens(
            "\n".join(l.text for l in current_lines)
        )
        chunk.finalize()
        chunks.append(chunk)

    logger.info(
        "Created %d chunks from %d compact lines", len(chunks), len(compact_lines)
    )
    for i, ch in enumerate(chunks):
        logger.debug(
            "  Chunk %d: lines L%d-L%d, %d entries, ~%d tokens",
            i, ch.start_line, ch.end_line, len(ch.lines), ch.estimated_tokens,
        )

    return chunks


# -----------------------------------------------------------------------
# Main pipeline: file → chunks
# -----------------------------------------------------------------------

def split_log_file(
    file_path: str,
    estimator: TokenEstimator | None = None,
) -> tuple[list[LogChunk], TokenEstimator, list[ParsedEntry]]:
    """
    Full pipeline: read a log file and split it into model-ready chunks.

    Returns:
        - List of LogChunk objects ready for the model
        - The TokenEstimator used (possibly calibrated later)
        - List of all ParsedEntry objects (for state table building)

    We keep all_entries in a list because the state table needs access
    to the parsed data of every line. For a ~94KB log (~258 lines),
    this is fine for memory.
    """
    if estimator is None:
        estimator = TokenEstimator()

    # Read all entries (streaming from file, but storing for state table)
    all_entries = list(read_entries(file_path))
    logger.info("Read %d entries from %s", len(all_entries), file_path)

    # Deduplicate
    compact_lines = deduplicate(all_entries)

    # Chunk
    chunks = chunk_lines(compact_lines, estimator)

    return chunks, estimator, all_entries

