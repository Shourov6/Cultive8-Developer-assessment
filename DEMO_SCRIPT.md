# Hiring Assessment Demo Script

**Project**: Local AI Security Log Analyzer  
**Duration**: 3 to 5 minutes  
**Goal**: Explain the design, show live execution, and demonstrate why this solution is technically robust under hard resource limits.

---

## 1. Introduction (30 seconds)
- *"Hi everyone, today I'm demonstrating the Local AI Security Log Analyzer."*
- **Problem Statement**:
  - *"We have large server logs—over 20,000 tokens—containing complex cyber attack patterns."*
  - *"Our constraint is strict: a local model (Qwen3.5 2B on Ollama) with only a 2,048-token context window, 2 vCPU, no GPU, and a 4 GB RAM ceiling."*
- **Key Challenge**:
  - *"How do you analyze a 20,000-token log with a 2,048-token model without missing attacks that span across parts of the file?"*

---

## 2. Technical Architecture & Innovation (60 seconds)
- **Log Splitting & Compact Formatting** (`app/splitter.py`):
  - *"We never cut entries in half. We parse every JSON line, preserve 1-based line numbers, and convert each line to a compact format that strips noise fields (request IDs, long User-Agents, response sizes) while keeping all security attributes."*
  - *"We calibrate token estimation dynamically from Ollama's `prompt_eval_count`."*
- **Deterministic Cross-Chunk Memory** (`app/state.py`):
  - *"The model doesn't own memory—our code does. We track an in-memory StateTable across chunks for IPs and accounts."*
  - *"Before each model call, we inject a short carried-context summary (≤ 350 tokens) of high-risk entities."*
- **Prompt Injection Defense** (`app/prompts.py`):
  - *"We treat log data strictly as untrusted input between `<LOG_DATA>` delimiters. Hostile commands like 'Ignore previous instructions' are detected deterministically and flagged as attacks rather than executed."*

---

## 3. Live Demonstration (90 seconds)
1. **Launch the App**:
   ```bash
   python -m uvicorn app.main:app --port 8000
   ```
2. **Open Dashboard** (`http://localhost:8000`):
   - Highlight the **RAM usage badge**: ~170 MB used out of the 4,096 MB budget.
   - Highlight the **local model badge**: `qwen3.5:2b`, 100% offline.
3. **Upload the Sample Log**:
   - Drag and drop `Cultive8_Workspace_Agrigen_Server.log`.
   - Click **"Start Security Analysis"**.
4. **Walk Through the Progress & Findings**:
   - Watch the chunk progress bar and token metrics update live.
   - Show the final consolidated report:
     - **Critical**: `203.0.113.44` / `workspace.admin` — Brute force followed by account compromise and 2.8 MB data exfiltration.
     - **High**: `203.0.113.72` — SQL injection (`' OR 1=1--`, `UNION SELECT`, `SLEEP(5)`).
     - **High**: `203.0.113.90` — Reconnaissance probing (`.env`, `.git`, `phpmyadmin`) and directory traversal (`../../etc/passwd`).
     - **High**: `203.0.113.201` — Adversarial prompt injection attempt in support messages.
     - **Medium**: `203.0.113.155` — High-frequency burst triggering HTTP 429 rate limits.
     - **Noise Rejection**: Routine health checks, deploy maintenance 503s, and transient DB retries were correctly ignored!

---

## 4. Proving Generality (45 seconds)
- *"To prove our solution has zero hardcoded values, we built a synthetic generator (`tools/make_sample_log.py`)."*
- Run the test suite:
  ```bash
  python -m pytest tests/ -v
  ```
  - Highlight: **73 unit and integration tests passing in ~6 seconds**.
- Run the generator:
  ```bash
  python tools/make_sample_log.py
  ```
  - Show that the analyzer detects completely different planted IPs and attack vectors with identical accuracy.

---

## 5. Summary & Questions (15 seconds)
- *"In summary: Clean architecture, deterministic state management, strict context enforcement, and zero cloud dependencies—delivering reliable local security intelligence under constrained compute."*
- *"I'm ready for your questions!"*

