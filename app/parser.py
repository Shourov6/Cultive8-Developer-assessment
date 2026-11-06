"""
parser.py - Robust JSON parsing and repair for model responses.

The local model sometimes returns imperfect JSON (extra text, code fences,
trailing commas, truncated output). This module tries multiple strategies
to extract valid JSON before giving up.

Strategies (in order):
  1. Direct json.loads
  2. Strip markdown code fences and surrounding text
  3. Extract the largest balanced { ... } or [ ... ] block
  4. If all fail, return None so the caller can retry or mark as failed

Also provides validation for finding objects (severity enums, required fields).
"""

import json
import re
import logging

logger = logging.getLogger(__name__)

# Valid severity levels (case-insensitive matching, normalized to title case)
VALID_SEVERITIES = {"low", "medium", "high", "critical"}

# Required fields for a valid finding
REQUIRED_FINDING_FIELDS = {"attack_type", "severity"}


def parse_json_response(text: str) -> dict | list | None:
    """
    Try to parse the model's response as JSON using progressively
    more tolerant strategies.

    Returns the parsed object/list, or None if all strategies fail.
    """
    if not text or not text.strip():
        logger.warning("Empty response text")
        return None

    text = text.strip()

    # Strategy 1: Direct parse
    result = _try_direct(text)
    if result is not None:
        logger.debug("Parsed with direct json.loads")
        return result

    # Strategy 2: Strip code fences (```json ... ```) and surrounding text
    result = _try_strip_fences(text)
    if result is not None:
        logger.debug("Parsed after stripping code fences")
        return result

    # Strategy 3: Extract largest balanced braces
    result = _try_extract_balanced(text)
    if result is not None:
        logger.debug("Parsed by extracting balanced braces")
        return result

    logger.warning("All JSON parse strategies failed. Raw text: %s", text[:200])
    return None


def _try_direct(text: str) -> dict | list | None:
    """Try json.loads on the raw text."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _try_strip_fences(text: str) -> dict | list | None:
    """
    Strip markdown code fences like ```json ... ``` or ``` ... ```
    and any text before/after them.
    """
    # Pattern: optional ```json or ``` at start, content, ``` at end
    pattern = r'```(?:json)?\s*\n?(.*?)\n?\s*```'
    match = re.search(pattern, text, re.DOTALL)
    if match:
        inner = match.group(1).strip()
        try:
            return json.loads(inner)
        except (json.JSONDecodeError, ValueError):
            pass

    # Also try stripping any leading non-JSON text before { or [
    for start_char in ['{', '[']:
        idx = text.find(start_char)
        if idx > 0:
            trimmed = text[idx:]
            try:
                return json.loads(trimmed)
            except (json.JSONDecodeError, ValueError):
                pass

    return None


def _try_extract_balanced(text: str) -> dict | list | None:
    """
    Find the largest balanced { ... } or [ ... ] block in the text.
    Handles nested braces. Useful when the model adds commentary
    around the JSON.
    """
    best = None
    best_len = 0

    for open_char, close_char in [('{', '}'), ('[', ']')]:
        for i, ch in enumerate(text):
            if ch == open_char:
                depth = 0
                in_string = False
                escape_next = False

                for j in range(i, len(text)):
                    c = text[j]

                    if escape_next:
                        escape_next = False
                        continue

                    if c == '\\' and in_string:
                        escape_next = True
                        continue

                    if c == '"' and not escape_next:
                        in_string = not in_string
                        continue

                    if in_string:
                        continue

                    if c == open_char:
                        depth += 1
                    elif c == close_char:
                        depth -= 1
                        if depth == 0:
                            candidate = text[i:j + 1]
                            if len(candidate) > best_len:
                                try:
                                    parsed = json.loads(candidate)
                                    best = parsed
                                    best_len = len(candidate)
                                except (json.JSONDecodeError, ValueError):
                                    pass
                            break

    return best


def validate_finding(finding: dict) -> dict | None:
    """
    Validate and normalize a single finding dict from the model.

    - Checks required fields exist.
    - Normalizes severity to title case and validates enum.
    - Returns the cleaned finding, or None if invalid.
    """
    if not isinstance(finding, dict):
        return None

    # Check required fields
    for field in REQUIRED_FINDING_FIELDS:
        if field not in finding:
            logger.debug("Finding missing required field '%s': %s", field, finding)
            return None

    # Normalize severity
    severity = str(finding.get("severity", "")).strip().lower()
    if severity not in VALID_SEVERITIES:
        logger.debug("Invalid severity '%s', defaulting to 'Medium'", severity)
        severity = "medium"
    finding["severity"] = severity.title()  # "Low", "Medium", "High", "Critical"

    # Ensure attack_type is a non-empty string
    if not finding.get("attack_type") or not isinstance(finding["attack_type"], str):
        return None

    # Normalize optional fields with defaults
    finding.setdefault("entity", "unknown")
    finding.setdefault("reason", "")
    finding.setdefault("suggested_action", "")
    finding.setdefault("confidence", "suspected")
    finding.setdefault("evidence", [])

    # Normalize confidence
    conf = str(finding.get("confidence", "suspected")).strip().lower()
    if conf not in ("suspected", "confirmed"):
        conf = "suspected"
    finding["confidence"] = conf

    # Ensure evidence is a list
    if not isinstance(finding["evidence"], list):
        finding["evidence"] = []

    return finding


def validate_chunk_response(parsed: dict | list | None) -> list[dict]:
    """
    Validate the full parsed response from a chunk analysis call.

    Expected format:
        { "findings": [...], "notes": "..." }
    or just a list of findings.

    Returns a list of validated finding dicts (possibly empty).
    """
    if parsed is None:
        return []

    findings_raw = []

    if isinstance(parsed, list):
        findings_raw = parsed
    elif isinstance(parsed, dict):
        # Look for a "findings" key
        if "findings" in parsed:
            findings_raw = parsed["findings"]
            if not isinstance(findings_raw, list):
                findings_raw = [findings_raw] if isinstance(findings_raw, dict) else []
        else:
            # Maybe the dict itself is a single finding
            findings_raw = [parsed]
    else:
        return []

    # Validate each finding
    validated = []
    for f in findings_raw:
        clean = validate_finding(f)
        if clean is not None:
            validated.append(clean)

    logger.info(
        "Validated %d/%d findings from model response",
        len(validated), len(findings_raw),
    )
    return validated

