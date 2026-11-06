# Local AI Security Log Analyzer

A lightweight, production-grade web application that leverages a **local language model (Qwen3.5 2B via Ollama)** to detect and correlate cyber attacks across large server logs (~20,000+ tokens) within a **strict 2,048-token context window** and **4 GB total RAM ceiling**.

---

## Architecture Overview

```
                                      +--------------------------+
                                      |   Uploaded Server Log    |
                                      +--------------------------+
                                                   |
                                                   v
                                      +--------------------------+
                                      | Stream-Reader & Filter   |
                                      +--------------------------+
                                                   |
                                                   v
+------------------------+            +--------------------------+
|  Deterministic State   | <--------> |  Token-Budget Chunker    |
| Table (Entity Memory)  |            | (Budget: <= 950 tokens)  |
+------------------------+            +--------------------------+
           |                                       |
           | Carried Context                       v
           +------------------------> +--------------------------+
                                      |   Local Ollama Qwen3.5   |
                                      | (num_ctx=2048, threads=2)|
                                      +--------------------------+
                                                   |
                                                   v
                                      +--------------------------+
                                      | Multi-Strategy JSON      |
                                      | Repair & Validation      |
                                      +--------------------------+
                                                   |
                                                   v
                                      +--------------------------+
                                      | Cross-Chunk Correlation  |
                                      | Engine & Final Report    |
                                      +--------------------------+
```

---

## Key Engineering Highlights

1. **Strict Context Budgeting (`num_ctx = 2048`)**:
   - The log file exceeds 20,000 tokens. The engine converts raw lines to ultra-compact representations, dropping noise fields (long User-Agents, request IDs, response bytes) while preserving all security attributes.
   - Dynamic token calibration continually measures characters-per-token against Ollama's `prompt_eval_count`.

2. **Cross-Chunk Memory Owned by Code (Not the Model)**:
   - A persistent `StateTable` tracks entity activity across chunks (login failures, successes, 4xx/5xx patterns, SQLi signatures, traversal probes, rate limits).
   - Before each chunk, a compact carried-context summary (≤ 350 tokens) is passed to the model.
   - Example correlation: An entity attempting brute force across Chunks 0, 1, 2, succeeding in Chunk 7, and exporting data in Chunk 8 is linked into a single **Critical** finding: `brute_force_and_account_takeover`.

3. **Untrusted Data & Prompt-Injection Defense**:
   - Log text is strictly enclosed in `<LOG_DATA>` delimiters.
   - The system prompt instructs the model that log contents are untrusted data and commands must never be executed. Attempts to alter prompt rules (e.g. *"Ignore previous instructions"*) are caught by deterministic heuristics and flagged as `prompt_injection_attempt`.

4. **Resource Bounds (4 GB RAM, 2 vCPU)**:
   - Single-worker queue guarantees only one model evaluation occurs at any time.
   - Model inference runs with `num_thread = 2`, `think = false`, and `format = "json"`.
   - Python backend + Ollama combined RAM stays under 500 MB (budget: 4,096 MB).

---

## Token Budget Breakdown (Target: 2,048 Tokens)

| Component | Token Allocation | Description |
|---|---|---|
| **System Prompt** | ~350 tokens | Security analyst persona, untrusted data rules, JSON schema |
| **Carried Context** | ~350 tokens | High-priority suspicious entities & recent activity summaries |
| **Log Chunk Text** | ~950 tokens | Compact log lines packed with a 0.85 safety margin |
| **Model Output (`num_predict`)** | ~400 tokens | Strict JSON response containing findings list & notes |
| **Total Call Budget** | **~2,048 tokens** | Hard context window ceiling |

---

## Setup & Execution

### 1. Prerequisites
- Python 3.11+
- [Ollama](https://ollama.com/) installed and running locally

### 2. Pull Local Model
```bash
ollama pull qwen3.5:2b
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Web Server
```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Open your browser at **`http://localhost:8000`**.

---

## Verification & Testing

### Run All Unit & Integration Tests (73 tests)
```bash
python -m pytest tests/ -v
```

### Run End-to-End Analysis on the Sample Log
```bash
python run_full_analysis.py
```

### Test Generality with Synthetic Log Generator
```bash
python tools/make_sample_log.py
python -c "
from app.splitter import split_log_file;
from app.state import StateTable;
from app.correlate import apply_deterministic_correlations;
chunks, _, _ = split_log_file('synthetic_server.log');
state = StateTable();
[state.update_from_chunk_lines(c.lines) for c in chunks];
print('Detections:', [f['attack_type'] for f in apply_deterministic_correlations([], state)])
"
```

---

## Known Limits & Architectural Tradeoffs

- **Small Parameter Classification**: Qwen3.5 2B occasionally outputs minor JSON syntax discrepancies or markdown wraps; our multi-stage parser (`parse_json_response`) handles direct parsing, markdown fence removal, and balanced brace extraction.
- **CPU Inference Speed**: On 2 vCPU with no GPU acceleration, local token generation takes ~10-25 seconds per chunk. Progress polling and asynchronous job management ensure the UI remains fully responsive.
- **Single Concurrent Job**: To guarantee the 4 GB RAM ceiling is never violated, a threading lock ensures only one analysis worker executes at a time.

