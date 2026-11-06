"""
config.py - Central configuration for the Log Analyzer.

All token budgets, model settings, and file limits live here.
Change these constants to tune behaviour without touching other code.
"""

import os

# ---------------------------------------------------------------------------
# Ollama / Model settings
# ---------------------------------------------------------------------------
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
MODEL_NAME = os.getenv("MODEL_NAME", "qwen3.5:2b")

# Hard context window sent to Ollama on every call.
MODEL_CONTEXT_WINDOW = 2048  # tokens — HARD LIMIT, do not increase

# CPU threads Ollama is allowed to use (matches 2-vCPU constraint).
MODEL_NUM_THREADS = 2

# ---------------------------------------------------------------------------
# Token budget per call  (must sum to <= MODEL_CONTEXT_WINDOW)
#
# | Slot              | Tokens | Purpose                           |
# |-------------------|--------|-----------------------------------|
# | System prompt     |  ~350  | Role, rules, JSON schema          |
# | Carried context   |  ~350  | Cross-chunk memory summary        |
# | Log chunk text    |  ~950  | Compact log lines for this chunk  |
# | Model reply       |  ~400  | num_predict cap                   |
# | Total             | ~2048  |                                   |
# ---------------------------------------------------------------------------
BUDGET_SYSTEM_PROMPT = 350   # tokens reserved for system prompt
BUDGET_CARRIED_CONTEXT = 350  # tokens reserved for memory summary
BUDGET_LOG_CHUNK = 950       # tokens reserved for log lines
BUDGET_MODEL_REPLY = 400     # num_predict cap (max output tokens)

# Conservative characters-per-token estimate (will be calibrated at runtime).
# Most English text averages ~3.5-4 chars/token; we start conservative.
INITIAL_CHARS_PER_TOKEN = 3.2

# Safety margin: we aim for this fraction of the budget (e.g. 0.85 = 85%).
TOKEN_SAFETY_MARGIN = 0.85

# Performance optimization: pre-scan chunks for provably benign routine traffic
# (static assets, routine 200 GETs with no security indicators) to save inference tokens/time
OPTIMIZE_SKIP_BENIGN_CHUNKS = os.getenv("OPTIMIZE_SKIP_BENIGN_CHUNKS", "true").lower() == "true"

# ---------------------------------------------------------------------------
# Reliability
# ---------------------------------------------------------------------------
OLLAMA_TIMEOUT_SECONDS = 180   # per-call timeout
OLLAMA_MAX_RETRIES = 3         # retries per chunk (with exponential backoff)
OLLAMA_RETRY_BACKOFF_BASE = 2  # seconds; retry waits base^attempt

# ---------------------------------------------------------------------------
# File upload limits
# ---------------------------------------------------------------------------
MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024   # 10 MB
ALLOWED_EXTENSIONS = {".log", ".txt"}

# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
JOBS_DIR = os.path.join(DATA_DIR, "jobs")

# ---------------------------------------------------------------------------
# Dashboard polling
# ---------------------------------------------------------------------------
POLL_INTERVAL_MS = 1500  # frontend polls every 1.5 s

