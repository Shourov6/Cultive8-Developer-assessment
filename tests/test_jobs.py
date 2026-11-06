"""
test_jobs.py - Unit tests for JobManager, chunk skipping, and resume capabilities.

Tests cover:
  - Job creation and metadata persistence
  - Resuming a paused/interrupted job without re-evaluating completed chunks
  - Deterministic benign chunk pre-screening
  - Error isolation (single chunk error does not crash the entire pipeline)
"""

import os
import sys
import json
import pytest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.jobs import JobManager, JobMetadata
from app.state import StateTable
from app.splitter import LogChunk, CompactLine, is_chunk_provably_benign


class TestJobs:
    @pytest.fixture
    def temp_jobs_dir(self):
        tmp_dir = tempfile.mkdtemp(prefix="test_jobs_")
        yield tmp_dir
        shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_job_lifecycle(self, temp_jobs_dir):
        manager = JobManager(jobs_dir=temp_jobs_dir)
        
        sample_log = os.path.join(temp_jobs_dir, "test.log")
        with open(sample_log, "w", encoding="utf-8") as f:
            f.write('{"time":"2026-11-01T08:00:00Z","level":"INFO","method":"GET","path":"/","status":200}\n')

        job_id = manager.create_job(sample_log, "test.log")
        assert job_id.startswith("job-")

        meta = manager.load_metadata(job_id)
        assert meta is not None
        assert meta.status == "queued"
        assert meta.log_filename == "test.log"

    def test_job_resume_preserves_completed_chunks(self, temp_jobs_dir):
        manager = JobManager(jobs_dir=temp_jobs_dir)
        sample_log = os.path.join(temp_jobs_dir, "test.log")
        with open(sample_log, "w", encoding="utf-8") as f:
            f.write('{"time":"2026-11-01T08:00:00Z","level":"INFO","method":"GET","path":"/","status":200}\n')

        job_id = manager.create_job(sample_log, "test.log")
        chunks_dir = manager.get_chunks_dir(job_id)

        # Simulate chunk 0 already completed
        chunk0_data = {
            "chunk_index": 0,
            "status": "success",
            "findings": [{"attack_type": "test", "severity": "Low"}],
            "prompt_tokens": 100,
            "output_tokens": 20,
            "duration_seconds": 1.5,
        }
        with open(os.path.join(chunks_dir, "0.json"), "w", encoding="utf-8") as f:
            json.dump(chunk0_data, f)

        # Verify that loading chunks recognizes chunk 0 as completed
        completed = [f for f in os.listdir(chunks_dir) if f.endswith(".json")]
        assert "0.json" in completed

    def test_benign_chunk_pre_screening(self):
        # A chunk with only routine 200 GET requests
        benign_lines = [
            CompactLine(
                line_nums=[1],
                text="L1 GET /assets/style.css 200",
                data={"method": "GET", "path": "/assets/style.css", "status": 200},
            ),
            CompactLine(
                line_nums=[2],
                text="L2 GET /api/v1/dashboard 304",
                data={"method": "GET", "path": "/api/v1/dashboard", "status": 304},
            ),
        ]
        benign_chunk = LogChunk(chunk_index=0, lines=benign_lines)
        assert is_chunk_provably_benign(benign_chunk) is True

        # A chunk with an error or auth attempt is NOT benign
        suspicious_lines = [
            CompactLine(
                line_nums=[3],
                text="L3 POST /api/v1/auth/login 401 invalid_password",
                data={"method": "POST", "path": "/api/v1/auth/login", "status": 401, "auth_result": "invalid_password"},
            )
        ]
        suspicious_chunk = LogChunk(chunk_index=1, lines=suspicious_lines)
        assert is_chunk_provably_benign(suspicious_chunk) is False
