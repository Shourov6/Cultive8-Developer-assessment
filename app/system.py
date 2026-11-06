"""
system.py - System monitoring helpers (RAM, process metrics, model tags).
"""

import psutil
from typing import Dict, Any
from app.config import OLLAMA_BASE_URL
from app.llm import OllamaClient


def get_ram_usage() -> Dict[str, Any]:
    """
    Returns resident set size (RSS) memory in MB for:
      - FastAPI backend process
      - Ollama process(es)
      - Combined total
    """
    proc = psutil.Process()
    backend_mb = proc.memory_info().rss / (1024 * 1024)

    ollama_mb = 0.0
    ollama_procs = 0
    for p in psutil.process_iter(["name", "memory_info"]):
        try:
            name = (p.info["name"] or "").lower()
            if "ollama" in name:
                mem = p.info["memory_info"]
                if mem:
                    ollama_mb += mem.rss / (1024 * 1024)
                    ollama_procs += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return {
        "backend_mb": round(backend_mb, 1),
        "ollama_mb": round(ollama_mb, 1),
        "combined_mb": round(backend_mb + ollama_mb, 1),
        "budget_mb": 4096.0,
        "ollama_process_count": ollama_procs,
    }

