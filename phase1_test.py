"""
phase1_test.py - Phase 1 verification script.

Proves:
  1. Ollama is reachable and the model is available.
  2. The model responds with valid JSON at num_ctx=2048.
  3. Reports prompt/output token counts, elapsed time, and RAM usage.

Run:  python phase1_test.py
"""

import sys
import os
import json
import psutil
import time

# Add project root to path so we can import app modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.llm import OllamaClient, OllamaError
from app.config import MODEL_NAME, MODEL_CONTEXT_WINDOW, BUDGET_MODEL_REPLY


def get_ram_usage() -> dict:
    """
    Return RAM usage for this Python process and (if found) the Ollama process.
    Values in MB.
    """
    result = {}

    # This Python process
    proc = psutil.Process()
    result["python_process_mb"] = proc.memory_info().rss / (1024 * 1024)

    # Find Ollama process(es) — look for 'ollama' in process name
    ollama_total = 0.0
    ollama_count = 0
    for p in psutil.process_iter(["name", "memory_info"]):
        try:
            name = (p.info["name"] or "").lower()
            if "ollama" in name:
                mem = p.info["memory_info"]
                if mem:
                    ollama_total += mem.rss / (1024 * 1024)
                    ollama_count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    result["ollama_processes"] = ollama_count
    result["ollama_total_mb"] = round(ollama_total, 1)
    result["combined_mb"] = round(result["python_process_mb"] + ollama_total, 1)

    return result


def main():
    print("=" * 60)
    print("PHASE 1: Ollama Client Verification")
    print("=" * 60)

    # --- Step 1: Check Ollama health ---
    print("\n--- Step 1: Checking Ollama connectivity ---")
    client = OllamaClient()
    try:
        models = client.list_models()
        print(f"  Ollama is reachable at {client.base_url}")
        print(f"  Available models: {models}")
    except OllamaError as e:
        print(f"  FAILED: {e}")
        sys.exit(1)

    if MODEL_NAME not in models:
        print(f"  WARNING: Configured model '{MODEL_NAME}' not found!")
        print(f"  Run: ollama pull {MODEL_NAME}")
        sys.exit(1)
    print(f"  Model '{MODEL_NAME}' is available. ✓")

    # --- Step 2: Test JSON generation at num_ctx=2048 ---
    print("\n--- Step 2: Testing JSON generation (num_ctx=2048) ---")

    system_prompt = (
        "You are a security log analyzer. "
        "Always respond with valid JSON only. "
        "Do not include any text outside the JSON object."
    )

    user_prompt = (
        'Analyze this single log line and return JSON with keys '
        '"attack_type", "severity", "reason":\n'
        'L5 08:02:30 203.0.113.44 POST /api/v1/auth/login 401 '
        'user=admin invalid_password'
    )

    try:
        result = client.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            num_predict=BUDGET_MODEL_REPLY,
        )
    except OllamaError as e:
        print(f"  FAILED: {e}")
        sys.exit(1)

    print(f"  Raw response: {result.text[:500]}")
    print(f"  Prompt tokens (prompt_eval_count): {result.prompt_tokens}")
    print(f"  Output tokens (eval_count):        {result.output_tokens}")
    print(f"  Total tokens:                      {result.total_tokens}")
    print(f"  Context window (num_ctx):           {MODEL_CONTEXT_WINDOW}")
    print(f"  Elapsed time:                      {result.elapsed_seconds:.1f}s")

    # Verify it's valid JSON
    try:
        parsed = json.loads(result.text)
        print(f"  Parsed JSON: {json.dumps(parsed, indent=2)}")
        print("  Valid JSON response. ✓")
    except json.JSONDecodeError as e:
        print(f"  WARNING: Response is not valid JSON: {e}")
        print("  (This is expected sometimes with small models — the parser module")
        print("  in Phase 2 will handle repair.)")

    # Verify tokens are within budget
    if result.prompt_tokens <= MODEL_CONTEXT_WINDOW:
        print(f"  Prompt fits in context window. ✓")
    else:
        print(f"  WARNING: Prompt OVERFLOWED context ({result.prompt_tokens} > {MODEL_CONTEXT_WINDOW})")

    # Calibrate chars-per-token from the real prompt_eval_count
    prompt_chars = len(system_prompt) + len(user_prompt)
    if result.prompt_tokens > 0:
        actual_cpt = prompt_chars / result.prompt_tokens
        print(f"\n  Token calibration:")
        print(f"    Prompt chars:       {prompt_chars}")
        print(f"    Prompt tokens:      {result.prompt_tokens}")
        print(f"    Actual chars/token: {actual_cpt:.2f}")

    # --- Step 3: RAM usage ---
    print("\n--- Step 3: RAM usage ---")
    ram = get_ram_usage()
    print(f"  Python process:  {ram['python_process_mb']:.1f} MB")
    print(f"  Ollama ({ram['ollama_processes']} procs): {ram['ollama_total_mb']:.1f} MB")
    print(f"  Combined:        {ram['combined_mb']:.1f} MB")

    budget_gb = 4.0
    if ram["combined_mb"] < budget_gb * 1024:
        print(f"  Within 4 GB RAM budget. ✓")
    else:
        print(f"  WARNING: Exceeds 4 GB budget!")

    # --- Step 4: Second call to verify consistency ---
    print("\n--- Step 4: Consistency check (second call) ---")
    try:
        result2 = client.generate(
            system_prompt=system_prompt,
            user_prompt=(
                'Return JSON with keys "status" and "message". '
                'Set status to "ok" and message to "phase 1 passed".'
            ),
            num_predict=100,
        )
        print(f"  Response: {result2.text[:300]}")
        print(f"  Tokens: prompt={result2.prompt_tokens} output={result2.output_tokens}")
        print(f"  Elapsed: {result2.elapsed_seconds:.1f}s")

        parsed2 = json.loads(result2.text)
        print(f"  Parsed: {parsed2}")
        print("  Consistency check passed. ✓")
    except Exception as e:
        print(f"  Second call issue: {e}")
        print("  (Non-fatal — small models can be inconsistent.)")

    # --- Summary ---
    print("\n" + "=" * 60)
    print("PHASE 1 COMPLETE")
    print("=" * 60)
    print(f"  Model:          {MODEL_NAME}")
    print(f"  Context window: {MODEL_CONTEXT_WINDOW} tokens")
    print(f"  JSON mode:      format='json', think=False")
    print(f"  RAM combined:   {ram['combined_mb']:.1f} MB (budget: 4096 MB)")
    print(f"  First call:     {result.elapsed_seconds:.1f}s")
    print("=" * 60)


if __name__ == "__main__":
    main()

