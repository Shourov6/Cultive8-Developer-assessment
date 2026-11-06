"""
system.py - System monitoring helpers (RAM, process metrics, model tags).

Calculates realistic system memory usage:
  - FastAPI backend process RSS
  - Ollama runner & host processes RSS
  - Ollama model weights resident in system RAM (from /api/ps)
Ensures total memory is accurately displayed against the 4,096 MB budget limit.
"""

import logging
import psutil
from typing import Dict, Any
from app.config import OLLAMA_BASE_URL
from app.llm import OllamaClient

logger = logging.getLogger(__name__)


def get_ram_usage() -> Dict[str, Any]:
    """
    Returns memory breakdown in MB for:
      - FastAPI backend process RSS
      - Ollama process(es) RSS
      - Model weights resident in system RAM
      - Combined total memory footprint
    """
    proc = psutil.Process()
    backend_mb = proc.memory_info().rss / (1024 * 1024)

    # 1. Host processes for Ollama
    ollama_process_mb = 0.0
    ollama_procs = 0
    for p in psutil.process_iter(["name", "memory_info"]):
        try:
            name = (p.info["name"] or "").lower()
            if "ollama" in name:
                mem = p.info["memory_info"]
                if mem:
                    ollama_process_mb += mem.rss / (1024 * 1024)
                    ollama_procs += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # 2. Query Ollama /api/ps for actual model weights resident in system RAM
    model_ram_mb = 0.0
    try:
        import httpx
        resp = httpx.get(f"{OLLAMA_BASE_URL}/api/ps", timeout=2.0)
        if resp.status_code == 200:
            data = resp.json()
            for m in data.get("models", []):
                # When running on CPU with no GPU, size is held in system RAM
                size_bytes = m.get("size", 0)
                vram_bytes = m.get("size_vram", 0)
                ram_bytes = max(0, size_bytes - vram_bytes) if vram_bytes else size_bytes
                model_ram_mb += ram_bytes / (1024 * 1024)
    except Exception as e:
        logger.debug("Ollama /api/ps query failed: %s", e)

    # If model is currently unloaded/idle, use model size from /api/tags or known Qwen3.5 2B Q8_0 footprint (~2.2 GB)
    if model_ram_mb == 0.0:
        try:
            import httpx
            resp = httpx.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=2.0)
            if resp.status_code == 200:
                for m in resp.json().get("models", []):
                    if "qwen3.5:2b" in m.get("name", ""):
                        model_ram_mb = m.get("size", 0) / (1024 * 1024)
                        break
        except Exception:
            model_ram_mb = 2233.8

    ollama_total_mb = ollama_process_mb + model_ram_mb
    combined_mb = backend_mb + ollama_total_mb

    return {
        "backend_mb": round(backend_mb, 1),
        "ollama_process_mb": round(ollama_process_mb, 1),
        "model_ram_mb": round(model_ram_mb, 1),
        "ollama_mb": round(ollama_total_mb, 1),
        "combined_mb": round(combined_mb, 1),
        "budget_mb": 4096.0,
        "ollama_process_count": ollama_procs,
    }
