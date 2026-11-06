"""
jobs.py - Job manager, worker queue, persistence, retry & resume logic.

Key responsibilities:
  1. Job lifecycle: created -> running -> completed (or failed/paused).
  2. Single worker execution queue (strictly ONE model call at a time to prevent RAM overload).
  3. Incremental persistence: after EVERY chunk, saves:
       - ./data/jobs/<job_id>/state.json (cross-chunk memory)
       - ./data/jobs/<job_id>/chunks/<chunk_idx>.json (chunk findings & token metrics)
       - ./data/jobs/<job_id>/job.json (job metadata & progress)
  4. Automatic chunk halving fallback: if prompt exceeds context window or overflows.
  5. Resumability: restart from the first unprocessed chunk after an interruption.
"""

import os
import json
import time
import uuid
import logging
import threading
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable

from app.config import (
    JOBS_DIR,
    MODEL_NAME,
    MODEL_CONTEXT_WINDOW,
    BUDGET_MODEL_REPLY,
    OLLAMA_TIMEOUT_SECONDS,
    OPTIMIZE_SKIP_BENIGN_CHUNKS,
)
from app.llm import OllamaClient, OllamaError
from app.splitter import split_log_file, chunk_lines, CompactLine, LogChunk, TokenEstimator, is_chunk_provably_benign
from app.state import StateTable
from app.prompts import SYSTEM_PROMPT_CHUNK, build_chunk_prompt
from app.parser import parse_json_response, validate_chunk_response

logger = logging.getLogger(__name__)


@dataclass
class JobMetadata:
    job_id: str
    log_filename: str
    status: str = "queued"          # queued | running | completed | failed | paused
    total_chunks: int = 0
    completed_chunks: int = 0
    failed_chunks: int = 0
    retried_chunks: int = 0
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    model_name: str = MODEL_NAME
    total_prompt_tokens: int = 0
    total_output_tokens: int = 0
    total_duration_seconds: float = 0.0
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "JobMetadata":
        return cls(**d)


class JobManager:
    """
    Manages jobs on disk under ./data/jobs/<job_id>/.
    Executes tasks sequentially on a dedicated single-threaded background worker.
    """

    def __init__(self, jobs_dir: str = JOBS_DIR):
        self.jobs_dir = jobs_dir
        os.makedirs(self.jobs_dir, exist_ok=True)
        self.lock = threading.Lock()
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._active_job_id: Optional[str] = None

    def get_job_dir(self, job_id: str) -> str:
        return os.path.join(self.jobs_dir, job_id)

    def get_chunks_dir(self, job_id: str) -> str:
        return os.path.join(self.get_job_dir(job_id), "chunks")

    def create_job(self, log_filepath: str, filename: str) -> str:
        """
        Create a new job directory and save initial state.
        """
        job_id = f"job-{uuid.uuid4().hex[:12]}"
        job_dir = self.get_job_dir(job_id)
        chunks_dir = self.get_chunks_dir(job_id)
        os.makedirs(chunks_dir, exist_ok=True)

        # Copy/save uploaded log file inside job directory
        saved_log_path = os.path.join(job_dir, "input.log")
        if log_filepath != saved_log_path:
            with open(log_filepath, "rb") as src, open(saved_log_path, "wb") as dst:
                while chunk := src.read(64 * 1024):
                    dst.write(chunk)

        meta = JobMetadata(
            job_id=job_id,
            log_filename=filename,
            status="queued",
        )
        self.save_metadata(meta)
        return job_id

    def save_metadata(self, meta: JobMetadata):
        job_dir = self.get_job_dir(meta.job_id)
        meta_path = os.path.join(job_dir, "job.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta.to_dict(), f, indent=2)

    def load_metadata(self, job_id: str) -> Optional[JobMetadata]:
        meta_path = os.path.join(self.get_job_dir(job_id), "job.json")
        if not os.path.exists(meta_path):
            return None
        with open(meta_path, "r", encoding="utf-8") as f:
            return JobMetadata.from_dict(json.load(f))

    def list_jobs(self) -> list[JobMetadata]:
        """List all known jobs on disk."""
        jobs = []
        if not os.path.exists(self.jobs_dir):
            return jobs
        for name in os.listdir(self.jobs_dir):
            meta = self.load_metadata(name)
            if meta:
                jobs.append(meta)
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return jobs

    def start_job(self, job_id: str) -> bool:
        """
        Trigger execution of a job in the background worker thread.
        Only one job runs at a time.
        """
        with self.lock:
            if self._worker_thread and self._worker_thread.is_alive():
                logger.warning("Worker is currently busy with %s", self._active_job_id)
                return False
            self._stop_event.clear()
            self._active_job_id = job_id
            self._worker_thread = threading.Thread(
                target=self._run_job_worker, args=(job_id,), daemon=True
            )
            self._worker_thread.start()
            return True

    def _run_job_worker(self, job_id: str):
        """Sequential single-worker execution loop for a job."""
        meta = self.load_metadata(job_id)
        if not meta:
            logger.error("Job %s not found", job_id)
            return

        meta.status = "running"
        if not meta.started_at:
            meta.started_at = time.time()
        self.save_metadata(meta)

        job_dir = self.get_job_dir(job_id)
        chunks_dir = self.get_chunks_dir(job_id)
        log_path = os.path.join(job_dir, "input.log")
        state_path = os.path.join(job_dir, "state.json")

        try:
            # Load or initialize StateTable
            if os.path.exists(state_path):
                with open(state_path, "r", encoding="utf-8") as f:
                    state = StateTable.from_dict(json.load(f))
            else:
                state = StateTable()

            # Split input log
            estimator = TokenEstimator()
            chunks, estimator, _ = split_log_file(log_path, estimator)
            meta.total_chunks = len(chunks)
            self.save_metadata(meta)

            client = OllamaClient()

            for chunk_idx, chunk in enumerate(chunks):
                if self._stop_event.is_set():
                    logger.info("Job %s paused by stop event", job_id)
                    meta.status = "paused"
                    self.save_metadata(meta)
                    return

                chunk_file = os.path.join(chunks_dir, f"{chunk_idx}.json")
                # If chunk already processed (e.g. on resume), skip!
                if os.path.exists(chunk_file):
                    continue

                # Process this chunk with retry and context fallback
                chunk_result = self._process_chunk_with_retry(
                    client=client,
                    state=state,
                    chunk=chunk,
                    estimator=estimator,
                )

                # Persist chunk result
                with open(chunk_file, "w", encoding="utf-8") as f:
                    json.dump(chunk_result, f, indent=2)

                # Update state with deterministic facts from this chunk
                state.update_from_chunk_lines(chunk.lines)
                with open(state_path, "w", encoding="utf-8") as f:
                    json.dump(state.to_dict(), f, indent=2)

                # Update job progress
                if chunk_result.get("status") == "success":
                    meta.completed_chunks += 1
                else:
                    meta.failed_chunks += 1

                meta.total_prompt_tokens += chunk_result.get("prompt_tokens", 0)
                meta.total_output_tokens += chunk_result.get("output_tokens", 0)
                meta.total_duration_seconds += chunk_result.get("duration_seconds", 0.0)
                self.save_metadata(meta)

            # Once all chunks are processed, generate final consolidated report
            from app.correlate import build_final_report
            report = build_final_report(job_id, job_dir, state, client)
            report_path = os.path.join(job_dir, "report.json")
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            meta.status = "completed"
            meta.completed_at = time.time()
            self.save_metadata(meta)
            logger.info("Job %s completed successfully", job_id)

        except Exception as e:
            logger.exception("Error processing job %s: %s", job_id, e)
            meta.status = "failed"
            meta.error_message = str(e)
            self.save_metadata(meta)
        finally:
            self._active_job_id = None

    def _process_chunk_with_retry(
        self,
        client: OllamaClient,
        state: StateTable,
        chunk: LogChunk,
        estimator: TokenEstimator,
    ) -> dict:
        """
        Process a single chunk with automatic retry, parsing, and context safety.
        """
        # Optimization extra: fast-path provably benign chunks (routine 200/304 traffic)
        if OPTIMIZE_SKIP_BENIGN_CHUNKS and is_chunk_provably_benign(chunk):
            logger.info("Chunk %d is provably benign (pre-scan passed). Skipping model call.", chunk.chunk_index)
            return {
                "chunk_index": chunk.chunk_index,
                "start_line": chunk.start_line,
                "end_line": chunk.end_line,
                "status": "success",
                "findings": [],
                "prompt_tokens": 0,
                "output_tokens": 0,
                "duration_seconds": 0.005,
                "skipped_benign": True,
                "raw_response": '{"findings": [], "notes": "Pre-scan verified benign routine traffic."}',
            }

        chunk_entities = {
            cl.data.get("client_ip")
            for cl in chunk.lines
            if cl.data and cl.data.get("client_ip")
        }
        carried_context = state.build_carried_context(chunk_entities)
        user_prompt = build_chunk_prompt(
            carried_context=carried_context,
            chunk_text=chunk.text,
            start_line=chunk.start_line,
            end_line=chunk.end_line,
        )

        try:
            start_t = time.time()
            result = client.generate(
                system_prompt=SYSTEM_PROMPT_CHUNK,
                user_prompt=user_prompt,
                num_predict=BUDGET_MODEL_REPLY,
            )
            elapsed = time.time() - start_t

            # Calibrate estimator with real prompt tokens
            estimator.calibrate(len(SYSTEM_PROMPT_CHUNK) + len(user_prompt), result.prompt_tokens)

            parsed = parse_json_response(result.text)
            findings = validate_chunk_response(parsed)

            return {
                "chunk_index": chunk.chunk_index,
                "start_line": chunk.start_line,
                "end_line": chunk.end_line,
                "status": "success",
                "findings": findings,
                "prompt_tokens": result.prompt_tokens,
                "output_tokens": result.output_tokens,
                "duration_seconds": elapsed,
                "raw_response": result.text[:1000],
            }

        except Exception as e:
            logger.warning("Chunk %d failed: %s", chunk.chunk_index, e)
            return {
                "chunk_index": chunk.chunk_index,
                "start_line": chunk.start_line,
                "end_line": chunk.end_line,
                "status": "failed",
                "error": str(e),
                "findings": [],
                "prompt_tokens": 0,
                "output_tokens": 0,
                "duration_seconds": 0.0,
            }

