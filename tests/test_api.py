"""
test_api.py - Integration and endpoint testing for FastAPI server.

Tests cover:
  - Static dashboard serving
  - System telemetry routes (/api/system/ram, /api/system/models)
  - File upload validation (reject non-log, reject empty, accept valid)
  - Job status tracking and state retrieval
"""

import os
import io
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app

client = TestClient(app)


class TestApiEndpoints:
    def test_serve_dashboard(self):
        response = client.get("/")
        assert response.status_code == 200
        assert "Local AI Security Log Analyzer" in response.text

    def test_system_ram_endpoint(self):
        response = client.get("/api/system/ram")
        assert response.status_code == 200
        data = response.json()
        assert "backend_mb" in data
        assert "combined_mb" in data
        assert data["budget_mb"] == 4096.0

    def test_system_models_endpoint(self):
        response = client.get("/api/system/models")
        assert response.status_code == 200
        data = response.json()
        assert "active_model" in data

    def test_upload_invalid_extension(self):
        fake_file = io.BytesIO(b"malicious payload")
        response = client.post(
            "/api/upload",
            files={"file": ("malware.exe", fake_file, "application/octet-stream")},
        )
        assert response.status_code == 400
        assert "Invalid file extension" in response.json()["detail"]

    def test_upload_empty_file(self):
        empty_file = io.BytesIO(b"")
        response = client.post(
            "/api/upload",
            files={"file": ("empty.log", empty_file, "text/plain")},
        )
        assert response.status_code == 400
        assert "empty" in response.json()["detail"].lower()

    def test_upload_valid_log(self):
        valid_content = b'{"time":"2026-11-01T08:00:00Z","level":"INFO","message":"test"}\n'
        valid_file = io.BytesIO(valid_content)
        response = client.post(
            "/api/upload",
            files={"file": ("test.log", valid_file, "text/plain")},
        )
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data
        assert data["filename"] == "test.log"
        assert data["status"] == "queued"

        # Check job status endpoint
        job_id = data["job_id"]
        status_res = client.get(f"/api/jobs/{job_id}/status")
        assert status_res.status_code == 200
        status_data = status_res.json()
        assert status_data["job_id"] == job_id
        assert status_data["status"] == "queued"

    def test_report_not_ready_initially(self):
        valid_content = b'{"time":"2026-11-01T08:00:00Z","level":"INFO","message":"test"}\n'
        upload_res = client.post(
            "/api/upload",
            files={"file": ("test.log", io.BytesIO(valid_content), "text/plain")},
        )
        job_id = upload_res.json()["job_id"]

        rep_res = client.get(f"/api/jobs/{job_id}/report")
        assert rep_res.status_code == 404

    def test_cancel_job_endpoint(self):
        valid_content = b'{"time":"2026-11-01T08:00:00Z","level":"INFO","message":"test"}\n'
        upload_res = client.post(
            "/api/upload",
            files={"file": ("test.log", io.BytesIO(valid_content), "text/plain")},
        )
        job_id = upload_res.json()["job_id"]

        cancel_res = client.post(f"/api/jobs/{job_id}/cancel")
        assert cancel_res.status_code == 200
        assert cancel_res.json()["status"] == "cancelled"

        status_res = client.get(f"/api/jobs/{job_id}/status")
        assert status_res.status_code == 200
        assert status_res.json()["status"] == "cancelled"

    def test_load_sample_log_endpoint(self):
        res = client.post("/api/sample-log/load")
        assert res.status_code == 200
        data = res.json()
        assert "job_id" in data
        assert data["filename"] == "Cultive8_Workspace_Agrigen_Server.log"
        assert data["status"] == "queued"



