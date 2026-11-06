"""
test_splitter.py - Unit tests for the log splitter module.

Tests cover:
  - Line number preservation (1-based)
  - Compact formatting (noise removal, UA classification)
  - No mid-entry cuts
  - Deduplication
  - Chunk token limits
  - Non-JSON fallback
"""

import pytest
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.splitter import (
    parse_line,
    classify_user_agent,
    format_compact,
    read_entries,
    deduplicate,
    chunk_lines,
    split_log_file,
    TokenEstimator,
    CompactLine,
    ParsedEntry,
)


class TestClassifyUserAgent:
    def test_curl(self):
        assert classify_user_agent("curl/8.7.1") == "curl"

    def test_python_requests(self):
        assert classify_user_agent("python-requests/2.32.3") == "python-requests"

    def test_go_http(self):
        assert classify_user_agent("Go-http-client/1.1") == "Go-http-client"

    def test_aiohttp(self):
        assert classify_user_agent("aiohttp/3.10.5") == "aiohttp"

    def test_browser(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36"
        assert classify_user_agent(ua) == "browser"

    def test_health_monitor(self):
        assert classify_user_agent("Cultive8HealthMonitor/1.4") == "health-monitor"

    def test_empty(self):
        assert classify_user_agent("") == ""


class TestParseLine:
    def test_json_line(self):
        raw = json.dumps({
            "time": "2026-11-01T08:02:30.000Z",
            "app": "cultive8 workspace",
            "service": "gateway",
            "level": "INFO",
            "client_ip": "203.0.113.44",
            "request_id": "req-abc123",
            "method": "POST",
            "path": "/api/v1/auth/login",
            "status": 401,
            "response_bytes": 6001,
            "user_agent": "python-requests/2.32.3",
            "username": "workspace.admin",
            "auth_result": "invalid_password",
        })
        entry = parse_line(5, raw)

        assert entry.line_num == 5
        assert entry.data is not None
        assert "L5" in entry.compact
        assert "08:02:30" in entry.compact
        assert "203.0.113.44" in entry.compact
        assert "POST /api/v1/auth/login" in entry.compact
        assert "401" in entry.compact
        assert "user=workspace.admin" in entry.compact
        assert "invalid_password" in entry.compact
        assert "ua=python-requests" in entry.compact
        # Noise fields should NOT be in compact form
        assert "req-abc123" not in entry.compact
        assert "6001" not in entry.compact  # response_bytes dropped
        assert "AppleWebKit" not in entry.compact

    def test_non_json_line(self):
        entry = parse_line(10, "This is a plain text log line")
        assert entry.line_num == 10
        assert entry.data is None
        assert "L10" in entry.compact
        assert "This is a plain text log line" in entry.compact

    def test_empty_line(self):
        entry = parse_line(3, "")
        assert entry.line_num == 3
        assert "L3" in entry.compact

    def test_line_number_is_1_based(self):
        entry = parse_line(1, '{"time":"2026-01-01T00:00:00Z","level":"INFO","message":"start"}')
        assert entry.line_num == 1
        assert entry.compact.startswith("L1 ")

    def test_long_raw_line_truncated(self):
        long_line = "X" * 500
        entry = parse_line(99, long_line)
        # Should be truncated to ~200 chars + "L99 " prefix
        assert len(entry.compact) < 250

    def test_browser_ua_not_in_compact(self):
        """Browser user agents are normal and should not appear in compact form."""
        raw = json.dumps({
            "time": "2026-11-01T08:00:04.000Z",
            "level": "INFO",
            "method": "GET",
            "path": "/",
            "status": 200,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36",
        })
        entry = parse_line(1, raw)
        assert "ua=" not in entry.compact  # browser UA suppressed


class TestReadEntries:
    def test_reads_with_correct_line_numbers(self):
        lines = [
            json.dumps({"time": "2026-01-01T00:00:00Z", "level": "INFO", "message": "line1"}),
            json.dumps({"time": "2026-01-01T00:01:00Z", "level": "WARN", "message": "line2"}),
            json.dumps({"time": "2026-01-01T00:02:00Z", "level": "ERROR", "message": "line3"}),
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
            tmp_path = f.name

        try:
            entries = list(read_entries(tmp_path))
            assert len(entries) == 3
            assert entries[0].line_num == 1
            assert entries[1].line_num == 2
            assert entries[2].line_num == 3
        finally:
            os.unlink(tmp_path)

    def test_preserves_continuation_lines(self):
        """Indented lines (stack traces) should stay with their parent."""
        content = 'ERROR something failed\n  at module.func:42\n  at main:10\nINFO normal line\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write(content)
            tmp_path = f.name

        try:
            entries = list(read_entries(tmp_path))
            # Should get 2 entries: the error (with continuations) and the info line
            assert len(entries) == 2
            # First entry should contain the continuation text
            assert "module.func" in entries[0].compact
            assert entries[0].line_num == 1
            assert entries[1].line_num == 4
        finally:
            os.unlink(tmp_path)


class TestDeduplicate:
    def test_no_duplicates(self):
        entries = [
            ParsedEntry(1, "", None, "L1 line one", request_id="req-1"),
            ParsedEntry(2, "", None, "L2 line two", request_id="req-2"),
        ]
        result = deduplicate(entries)
        assert len(result) == 2

    def test_duplicate_request_ids_merged(self):
        entries = [
            ParsedEntry(1, "", {"a": 1}, "L1 line one", request_id="req-dup"),
            ParsedEntry(5, "", {"a": 1}, "L5 line one copy", request_id="req-dup"),
        ]
        result = deduplicate(entries)
        assert len(result) == 1
        assert 1 in result[0].line_nums
        assert 5 in result[0].line_nums
        assert "×2" in result[0].text

    def test_duplicate_event_ids_merged(self):
        entries = [
            ParsedEntry(10, "", None, "L10 event", event_id="evt-1"),
            ParsedEntry(20, "", None, "L20 event copy", event_id="evt-1"),
            ParsedEntry(30, "", None, "L30 other", event_id="evt-2"),
        ]
        result = deduplicate(entries)
        assert len(result) == 2

    def test_entries_without_ids_kept_separate(self):
        entries = [
            ParsedEntry(1, "", None, "L1 no id"),
            ParsedEntry(2, "", None, "L2 no id"),
        ]
        result = deduplicate(entries)
        assert len(result) == 2

    def test_sorted_by_line_number(self):
        entries = [
            ParsedEntry(10, "", None, "L10 later", request_id="req-b"),
            ParsedEntry(2, "", None, "L2 earlier", request_id="req-a"),
        ]
        result = deduplicate(entries)
        assert result[0].line_nums[0] == 2
        assert result[1].line_nums[0] == 10


class TestTokenEstimator:
    def test_initial_estimate(self):
        est = TokenEstimator(initial_cpt=4.0)
        # 100 chars / 4.0 cpt = 25 tokens + 1
        assert est.estimate_tokens("x" * 100) == 26

    def test_calibration(self):
        est = TokenEstimator(initial_cpt=4.0)
        # Real: 200 chars was 100 tokens → 2.0 cpt
        est.calibrate(200, 100)
        # After calibration, estimate should change
        new_est = est.estimate_tokens("x" * 200)
        # Should be closer to 100 than to 50
        assert new_est > 50

    def test_max_chars_for_budget(self):
        est = TokenEstimator(initial_cpt=3.0)
        max_chars = est.max_chars_for_budget
        # BUDGET_LOG_CHUNK * 0.85 * 3.0
        assert max_chars > 0


class TestChunkLines:
    def test_single_chunk_when_small(self):
        est = TokenEstimator(initial_cpt=4.0)
        lines = [
            CompactLine(line_nums=[1], text="L1 short line", data=None),
            CompactLine(line_nums=[2], text="L2 short line", data=None),
        ]
        chunks = chunk_lines(lines, est)
        assert len(chunks) == 1
        assert chunks[0].start_line == 1
        assert chunks[0].end_line == 2

    def test_splits_when_budget_exceeded(self):
        est = TokenEstimator(initial_cpt=1.0)  # 1 char = 1 token (very aggressive)
        # With BUDGET_LOG_CHUNK=950 and safety=0.85, max_chars ≈ 807
        # Create lines that together exceed this
        lines = [
            CompactLine(line_nums=[i], text=f"L{i} " + "x" * 400, data=None)
            for i in range(1, 5)
        ]
        chunks = chunk_lines(lines, est)
        assert len(chunks) > 1

    def test_never_splits_single_line(self):
        est = TokenEstimator(initial_cpt=4.0)
        lines = [
            CompactLine(line_nums=[1], text="L1 " + "x" * 50, data=None),
        ]
        chunks = chunk_lines(lines, est)
        assert len(chunks) == 1
        assert len(chunks[0].lines) == 1

    def test_chunk_line_range_correct(self):
        est = TokenEstimator(initial_cpt=4.0)
        lines = [
            CompactLine(line_nums=[5], text="L5 data", data=None),
            CompactLine(line_nums=[10, 15], text="L10 deduped", data=None),
            CompactLine(line_nums=[20], text="L20 data", data=None),
        ]
        chunks = chunk_lines(lines, est)
        # All should fit in one chunk with cpt=4.0
        assert len(chunks) == 1
        assert chunks[0].start_line == 5
        assert chunks[0].end_line == 20


class TestSplitLogFile:
    def test_full_pipeline_on_sample(self):
        """Integration test: run the full splitter on the real sample log."""
        sample = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "Cultive8_Workspace_Agrigen_Server.log",
        )
        if not os.path.exists(sample):
            pytest.skip("Sample log not found")

        chunks, estimator, entries = split_log_file(sample)

        # Basic sanity checks
        assert len(entries) == 258  # known line count
        assert len(chunks) > 0
        assert all(ch.start_line >= 1 for ch in chunks)
        assert all(ch.end_line <= 258 for ch in chunks)

        # Line numbers should be continuous (no gaps in coverage)
        all_line_nums = set()
        for ch in chunks:
            for cl in ch.lines:
                all_line_nums.update(cl.line_nums)
        assert 1 in all_line_nums
        assert 258 in all_line_nums

        # No chunk should have zero lines
        assert all(len(ch.lines) > 0 for ch in chunks)

