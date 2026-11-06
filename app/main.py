"""
main.py - FastAPI application entrypoint.

Exposes REST APIs for file uploads, job control, real-time status polling,
final report downloads, and system resource telemetry.
Serves the single-page dashboard at GET /.
"""

import os
import json
import tempfile
import logging
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.config import (
    MAX_UPLOAD_SIZE_BYTES,
    ALLOWED_EXTENSIONS,
    MODEL_NAME,
)
from app.system import get_ram_usage
from app.llm import OllamaClient, OllamaError
from app.jobs import JobManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("analyzer.main")

app = FastAPI(
    title="Local AI Security Log Analyzer",
    description="Offline security log analysis using local Qwen3.5 2B via Ollama",
    version="1.0.0",
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared JobManager instance
job_manager = JobManager()

# Static directory setup
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def serve_dashboard():
    """Serve the single-page web dashboard."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(index_path):
        return JSONResponse(
            status_code=404,
            content={"error": "Dashboard template not found. Please verify static/index.html exists."},
        )
    return FileResponse(index_path)


@app.get("/api/system/models")
def get_available_models():
    """List available local Ollama models and confirm connectivity."""
    client = OllamaClient()
    try:
        models = client.list_models()
        return {"connected": True, "active_model": MODEL_NAME, "models": models}
    except OllamaError as e:
        return {"connected": False, "active_model": MODEL_NAME, "error": str(e), "models": []}


@app.get("/api/system/ram")
def get_ram_metrics():
    """Live RAM metrics for backend and Ollama processes."""
    return get_ram_usage()


@app.post("/api/upload")
async def upload_log_file(file: UploadFile = File(...)):
    """
    Validate, stream to disk, and register a new log analysis job.
    Enforces strict file validation (extensions, size, text validity).
    """
    filename = file.filename or "uploaded.log"
    _, ext = os.path.splitext(filename.lower())

    # 1. Extension validation
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file extension '{ext}'. Only .log and .txt files are accepted.",
        )

    # 2. Stream directly to temporary file to enforce size limit without holding in RAM
    total_bytes = 0
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        tmp_path = tmp_file.name
        try:
            while chunk := await file.read(64 * 1024):
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File exceeds maximum allowed size ({MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB).",
                    )
                tmp_file.write(chunk)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    # 3. Non-empty check
    if total_bytes == 0:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    # 4. Text validity check (verify file can be decoded as text)
    try:
        with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
            sample = f.read(4096)
            if "\0" in sample:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="File appears to be binary, not valid text.",
                )
    except Exception as e:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Text verification failed: {e}",
        )

    # 5. Create job in persistence directory
    try:
        job_id = job_manager.create_job(tmp_path, filename)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    return {
        "job_id": job_id,
        "filename": filename,
        "size_bytes": total_bytes,
        "status": "queued",
    }


@app.post("/api/jobs/{job_id}/start")
def start_analysis_job(job_id: str):
    """Start analyzing an uploaded log file."""
    meta = job_manager.load_metadata(job_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Job not found.")

    if meta.status == "running":
        return {"message": "Job is already running.", "status": "running"}

    success = job_manager.start_job(job_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The analysis worker is currently busy with another job. Only one job runs at a time to respect the 4GB RAM ceiling.",
        )
    return {"message": "Analysis started successfully.", "job_id": job_id, "status": "running"}


@app.post("/api/jobs/{job_id}/resume")
def resume_analysis_job(job_id: str):
    """Resume an interrupted or paused job."""
    meta = job_manager.load_metadata(job_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Job not found.")

    success = job_manager.start_job(job_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Analysis worker is currently busy.",
        )
    return {"message": "Job resumed.", "job_id": job_id, "status": "running"}


@app.get("/api/jobs/{job_id}/status")
def get_job_status(job_id: str):
    """Poll job progress, chunk stats, and live system metrics."""
    meta = job_manager.load_metadata(job_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Job not found.")

    percent = 0
    if meta.total_chunks > 0:
        percent = int((meta.completed_chunks / meta.total_chunks) * 100)

    # Read all processed chunks for streaming telemetry
    chunks_summary = []
    chunks_dir = job_manager.get_chunks_dir(job_id)
    if os.path.exists(chunks_dir):
        chunk_files = [f for f in os.listdir(chunks_dir) if f.endswith(".json")]
        chunk_files.sort(key=lambda x: int(x.split(".")[0]) if x.split(".")[0].isdigit() else -1)
        for cf in chunk_files:
            try:
                with open(os.path.join(chunks_dir, cf), "r", encoding="utf-8") as f:
                    cdata = json.load(f)
                    chunks_summary.append({
                        "chunk_index": cdata.get("chunk_index", 0),
                        "start_line": cdata.get("start_line", 0),
                        "end_line": cdata.get("end_line", 0),
                        "status": cdata.get("status", "success"),
                        "prompt_tokens": cdata.get("prompt_tokens", 0),
                        "output_tokens": cdata.get("output_tokens", 0),
                        "duration_seconds": cdata.get("duration_seconds", 0.0),
                        "findings_count": len(cdata.get("findings", [])),
                        "skipped_benign": cdata.get("skipped_benign", False),
                    })
            except Exception:
                pass

    return {
        "job_id": meta.job_id,
        "filename": meta.log_filename,
        "status": meta.status,
        "total_chunks": meta.total_chunks,
        "completed_chunks": meta.completed_chunks,
        "failed_chunks": meta.failed_chunks,
        "progress_percent": percent,
        "total_prompt_tokens": meta.total_prompt_tokens,
        "total_output_tokens": meta.total_output_tokens,
        "total_duration_seconds": round(meta.total_duration_seconds, 1),
        "error_message": meta.error_message,
        "current_activity": meta.current_activity or "Processing...",
        "ram": get_ram_usage(),
        "chunks_summary": chunks_summary,
        "latest_chunk": chunks_summary[-1] if chunks_summary else None,
    }


@app.get("/api/jobs/{job_id}/report")
def get_job_report(job_id: str):
    """Retrieve final security report for a completed job."""
    meta = job_manager.load_metadata(job_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Job not found.")

    report_path = os.path.join(job_manager.get_job_dir(job_id), "report.json")
    if not os.path.exists(report_path):
        if meta.status == "running":
            raise HTTPException(status_code=400, detail="Job is still analyzing. Report is not yet ready.")
        raise HTTPException(status_code=404, detail="No report found for this job.")

    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/api/jobs")
def list_all_jobs():
    """List all registered jobs."""
    jobs = job_manager.list_jobs()
    return {"jobs": [j.to_dict() for j in jobs]}


@app.get("/api/jobs/unfinished")
def get_unfinished_job():
    """Detect any unfinished job that can be resumed after server restart."""
    jobs = job_manager.list_jobs()
    for j in jobs:
        if j.status in ("running", "paused", "queued") or (
            j.total_chunks > 0 and j.completed_chunks < j.total_chunks and j.status != "completed"
        ):
            return {"has_unfinished": True, "job": j.to_dict()}
    return {"has_unfinished": False, "job": None}


@app.post("/api/system/model")
def set_active_model(name: str):
    """Switch active local model for analyses (e.g. qwen3.5:2b, qwen3.5:0.8b)."""
    import app.config
    app.config.MODEL_NAME = name
    return {"status": "ok", "active_model": app.config.MODEL_NAME}


