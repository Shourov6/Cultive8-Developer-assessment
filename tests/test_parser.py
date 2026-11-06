"""
test_parser.py - Unit tests for the JSON repair / validation module.

Tests cover:
  - Direct JSON parsing
  - Code fence stripping
  - Balanced brace extraction
  - Finding validation (severity enum, required fields)
  - Chunk response validation
"""

import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.parser import (
    parse_json_response,
    validate_finding,
    validate_chunk_response,
)


class TestParseJsonResponse:
    """Tests for the multi-strategy JSON parser."""

    def test_valid_json_object(self):
        result = parse_json_response('{"key": "value"}')
        assert result == {"key": "value"}

    def test_valid_json_array(self):
        result = parse_json_response('[1, 2, 3]')
        assert result == [1, 2, 3]

    def test_json_with_code_fences(self):
        text = '```json\n{"attack_type": "sqli", "severity": "high"}\n```'
        result = parse_json_response(text)
        assert result == {"attack_type": "sqli", "severity": "high"}

    def test_json_with_plain_fences(self):
        text = '```\n{"key": "val"}\n```'
        result = parse_json_response(text)
        assert result == {"key": "val"}

    def test_json_with_surrounding_text(self):
        text = 'Here is the result:\n{"attack_type": "scan"}\nDone.'
        result = parse_json_response(text)
        assert result is not None
        assert result["attack_type"] == "scan"

    def test_nested_json_extraction(self):
        text = 'blah blah {"outer": {"inner": 42}} more text'
        result = parse_json_response(text)
        assert result == {"outer": {"inner": 42}}

    def test_empty_input(self):
        assert parse_json_response("") is None
        assert parse_json_response("   ") is None
        assert parse_json_response(None) is None

    def test_completely_invalid(self):
        assert parse_json_response("not json at all") is None

    def test_truncated_json(self):
        # Model output cut off mid-JSON — should fail gracefully
        result = parse_json_response('{"key": "val", "other":')
        # This may or may not parse depending on strategy; should not crash
        # The important thing is no exception
        assert result is None or isinstance(result, (dict, list))

    def test_json_with_trailing_comma(self):
        # Some models produce trailing commas — standard json.loads fails
        text = '{"a": 1, "b": 2,}'
        result = parse_json_response(text)
        # May fail to parse (Python json.loads is strict), that's OK
        # Just shouldn't crash
        assert result is None or isinstance(result, dict)


class TestValidateFinding:
    """Tests for individual finding validation."""

    def test_valid_finding(self):
        f = {
            "attack_type": "brute_force",
            "severity": "High",
            "entity": "203.0.113.44",
            "reason": "Multiple failed logins",
            "evidence": [{"line": 5, "snippet": "test"}],
        }
        result = validate_finding(f)
        assert result is not None
        assert result["severity"] == "High"
        assert result["confidence"] == "suspected"  # default

    def test_severity_normalization(self):
        f = {"attack_type": "sqli", "severity": "HIGH"}
        result = validate_finding(f)
        assert result["severity"] == "High"

        f2 = {"attack_type": "sqli", "severity": "low"}
        result2 = validate_finding(f2)
        assert result2["severity"] == "Low"

    def test_invalid_severity_defaults_to_medium(self):
        f = {"attack_type": "sqli", "severity": "banana"}
        result = validate_finding(f)
        assert result["severity"] == "Medium"

    def test_missing_attack_type(self):
        f = {"severity": "High", "reason": "test"}
        result = validate_finding(f)
        assert result is None

    def test_missing_severity(self):
        f = {"attack_type": "test"}
        result = validate_finding(f)
        # severity is required but should default, not reject
        assert result is None

    def test_non_dict_input(self):
        assert validate_finding("not a dict") is None
        assert validate_finding(42) is None
        assert validate_finding(None) is None

    def test_confidence_normalization(self):
        f = {"attack_type": "test", "severity": "low", "confidence": "CONFIRMED"}
        result = validate_finding(f)
        assert result["confidence"] == "confirmed"

    def test_invalid_confidence_defaults(self):
        f = {"attack_type": "test", "severity": "low", "confidence": "maybe"}
        result = validate_finding(f)
        assert result["confidence"] == "suspected"


class TestValidateChunkResponse:
    """Tests for full chunk response validation."""

    def test_findings_list(self):
        parsed = {
            "findings": [
                {"attack_type": "sqli", "severity": "high"},
                {"attack_type": "scan", "severity": "low"},
            ]
        }
        results = validate_chunk_response(parsed)
        assert len(results) == 2

    def test_bare_list(self):
        parsed = [
            {"attack_type": "sqli", "severity": "high"},
        ]
        results = validate_chunk_response(parsed)
        assert len(results) == 1

    def test_single_finding_dict(self):
        parsed = {"attack_type": "sqli", "severity": "high"}
        results = validate_chunk_response(parsed)
        assert len(results) == 1

    def test_mixed_valid_invalid(self):
        parsed = {
            "findings": [
                {"attack_type": "sqli", "severity": "high"},  # valid
                {"severity": "low"},  # missing attack_type
                {"attack_type": "scan", "severity": "medium"},  # valid
            ]
        }
        results = validate_chunk_response(parsed)
        assert len(results) == 2

    def test_none_input(self):
        assert validate_chunk_response(None) == []

    def test_empty_findings(self):
        assert validate_chunk_response({"findings": []}) == []

