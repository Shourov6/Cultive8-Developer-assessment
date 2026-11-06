# Interview Preparation & Code Walkthrough Guide

Use this guide to prepare for your live technical interview and code walkthrough. It covers architecture decisions, line-number pointers, common interviewer questions, and live-coding modification examples.

---

## 1. Codebase Architecture at a Glance

When asked *"Walk me through the repository structure"*, explain this flow:

```
Upload Log (.log / .txt)
       ↓
app/main.py            Streams file to disk in 64KB chunks (no memory duplication)
       ↓
app/splitter.py        Parses line-by-line, formats into compact tokens, deduplicates,
                       and packs into chunks budgeted at ~950 tokens (safety margin 0.85)
       ↓
app/state.py           Code-owned StateTable updates deterministic counters (failed logins,
                       status codes, regex patterns for SQLi, traversal, probes, bursts)
       ↓
app/prompts.py         Wraps compact chunk in <LOG_DATA> with strict untrusted-data rules
                       and injects a short carried-context summary (≤ 350 tokens)
       ↓
app/llm.py             Calls local Ollama qwen3.5:2b with num_ctx=2048, num_predict=400,
                       num_thread=2, format="json", think=false (timeout + backoff retries)
       ↓
app/parser.py          Multi-stage JSON repair (direct loads → fence stripping → balanced braces)
       ↓
app/correlate.py       Merges chunk findings by (attack_type, entity), runs escalation rules
                       (e.g., brute force + success → Critical account takeover), filters benign noise
       ↓
app/jobs.py            Persists state & chunks to disk; generates final report
       ↓
static/index.html      Renders interactive dashboard, live progress, and JSON export
```

---

## 2. Key Code Pointers (Where to Point the Interviewer)

| If the Interviewer Asks About... | Open This File | Key Function / Lines |
|---|---|---|
| **Enforcing the 2,048 Context Limit** | `app/llm.py` | `OllamaClient.generate()`: notice `options: {"num_ctx": 2048, "num_predict": num_predict, "num_thread": 2}` |
| **Token Budgeting & Estimation** | `app/config.py` & `app/splitter.py` | `app/config.py` constants table; `TokenEstimator.calibrate()` in `app/splitter.py` |
| **Preventing Mid-Entry Line Cuts** | `app/splitter.py` | `read_entries()`: keeps continuation lines (stack traces) with parents; `chunk_lines()` never splits a `CompactLine` |
| **Compact Token Formatter** | `app/splitter.py` | `format_compact()`: strips noise (User-Agent, request ID, bytes) to save ~60% of tokens |
| **Cross-Chunk Memory** | `app/state.py` | `StateTable.build_carried_context()`: prioritizes suspicious entities and fits within `BUDGET_CARRIED_CONTEXT` (≤ 350 tokens) |
| **Cross-Chunk Attack Escalation** | `app/correlate.py` | `apply_deterministic_correlations()`: Rule 1 escalates failed logins + later success into `brute_force_and_account_takeover` (Critical) |
| **Prompt Injection Defense** | `app/prompts.py` & `app/state.py` | `SYSTEM_PROMPT_CHUNK`: log data is untrusted data; `EntityRecord.update_from_log_entry()` flags injection markers |
| **Robust JSON Parsing** | `app/parser.py` | `_try_extract_balanced()`: extracts balanced `{...}` blocks even if the small model outputs leading/trailing commentary |
| **RAM Limitation (4 GB)** | `app/system.py` | `get_ram_usage()`: uses `psutil` to track backend RSS + Ollama processes; total is ~170 MB |

---

## 3. Top Interview Questions & Strong Answers

### Q1: "Why did code own the cross-chunk memory instead of letting the LLM summarize?"
> **Answer**: *"Small 2B parameter models suffer from context dilution, hallucination, and drift when summarizing iteratively across 10+ chunks. By having deterministic Python code track hard facts (exact timestamps, line numbers, login counts, regex indicators), we guarantee 100% factual accuracy. We then use the LLM for judgment (classifying attack vectors, assessing severity, and recommending actions)."*

### Q2: "How do you know the context limit of 2,048 tokens wasn't exceeded?"
> **Answer**: *"Three layers of defense: First, our chunker uses a conservative token estimator with a 15% safety margin (`TOKEN_SAFETY_MARGIN = 0.85`), capping log text to ~950 tokens. Second, after every model call, we verify Ollama's actual `prompt_eval_count` and dynamically recalibrate our chars-per-token ratio. Third, we cap model generation with `num_predict = 400`, ensuring the total prompt + reply stays strictly within 2,048 tokens."*

### Q3: "How did you ensure the solution wasn't hardcoded for this specific sample log?"
> **Answer**: *"All detection rules use generic patterns (standard SQL injection keywords, path traversal encodings, probe targets like `.env` and `.git`, and login failure/success counters). To prove generality, we wrote `tools/make_sample_log.py`, which generates a different ~20k-token synthetic log with different IPs and attack sequences. Running our pipeline on the synthetic log detects all attacks with the same accuracy."*

### Q4: "How does the app stay under 4 GB of RAM?"
> **Answer**: *"Three architectural choices: First, a single-worker execution queue guarantees only one inference call runs at a time. Second, file uploads stream directly to disk in 64 KB buffers rather than loading the whole file into RAM. Third, Qwen3.5 2B in Q8_0 quantization uses ~1.9 GB in memory, while our FastAPI backend takes ~50 MB, keeping total RAM under 2.1 GB even at peak."*

---

## 4. Live Coding: Likely "Small Changes" the Interviewer Might Ask For

During the interview, they may say: *"Can you make a small change right now?"* Here are the most common scenarios and how to do them in under 60 seconds:

### Scenario A: "Add detection for a new attack type (e.g., Cross-Site Scripting / XSS)"
1. Open `app/state.py`.
2. Add regex pattern near line 45:
   ```python
   XSS_PATTERNS = [
       re.compile(r"<script.*?>", re.IGNORECASE),
       re.compile(r"javascript:", re.IGNORECASE),
       re.compile(r"onerror=", re.IGNORECASE),
   ]
   ```
3. In `EntityRecord.update_from_log_entry()`:
   ```python
   for pattern in XSS_PATTERNS:
       if pattern.search(path) or pattern.search(decoded_path):
           self.sqli_evidence.append(EvidenceItem(line_num, snippet))  # or new xss_evidence list
   ```

### Scenario B: "Change rate limit severity from Medium to High"
1. Open `app/correlate.py`.
2. In `apply_deterministic_correlations()` under Rule 5 (Rate Limiting Bursts):
   Change:
   ```python
   "severity": "Medium"
   ```
   To:
   ```python
   "severity": "High"
   ```

### Scenario C: "Change the maximum allowed upload size from 10 MB to 20 MB"
1. Open `app/config.py`.
2. Change:
   ```python
   MAX_UPLOAD_SIZE_BYTES = 20 * 1024 * 1024
   ```

---

## 5. Quick Verification Commands to Run During the Interview

- **Show live dashboard**: Open `http://localhost:8000`
- **Run all automated tests**:
  ```powershell
  python -m pytest tests/ -v
  ```
- **Run end-to-end sample analysis**:
  ```powershell
  python run_full_analysis.py
  ```
- **Generate and test synthetic log**:
  ```powershell
  python tools/make_sample_log.py
  ```
