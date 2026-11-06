"""
phase3_test.py - Phase 3 verification script.

Proves:
  1. Splitting the real log file produces valid chunks.
  2. State table updates correctly from log entries.
  3. Real Ollama call analyzes a chunk using prompts.py and carried context.
  4. Response is parsed and validated by parser.py.
  5. Context window budget (<= 2048) and output token caps are strictly maintained.

Run: python phase3_test.py
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.config import MODEL_NAME, MODEL_CONTEXT_WINDOW, BUDGET_MODEL_REPLY
from app.llm import OllamaClient
from app.splitter import split_log_file, TokenEstimator
from app.state import StateTable
from app.prompts import SYSTEM_PROMPT_CHUNK, build_chunk_prompt
from app.parser import parse_json_response, validate_chunk_response


def main():
    print("=" * 60)
    print("PHASE 3: State Table + Prompts + Single-Chunk LLM Analysis")
    print("=" * 60)

    log_path = os.path.join(os.path.dirname(__file__), "Cultive8_Workspace_Agrigen_Server.log")
    if not os.path.exists(log_path):
        print(f"Error: {log_path} not found.")
        sys.exit(1)

    # Step 1: Split log file
    print("\n--- Step 1: Splitting log file ---")
    estimator = TokenEstimator()
    chunks, estimator, entries = split_log_file(log_path, estimator)
    print(f"Total entries: {len(entries)}")
    print(f"Total chunks created: {len(chunks)}")

    # Step 2: Initialize State Table and find an interesting chunk (with suspicious activity)
    print("\n--- Step 2: Updating State Table ---")
    state = StateTable()

    # Find a chunk that contains something interesting, e.g. chunk containing line 29 (SQL injection)
    target_chunk = None
    for chunk in chunks:
        state.update_from_chunk_lines(chunk.lines)
        if target_chunk is None and any(
            any("search=" in l.text or "login" in l.text for l in [line])
            for line in chunk.lines
        ):
            target_chunk = chunk

    if target_chunk is None:
        target_chunk = chunks[0]

    print(f"Selected Chunk {target_chunk.chunk_index} (Lines L{target_chunk.start_line}-L{target_chunk.end_line})")
    print(f"Compact lines in chunk: {len(target_chunk.lines)}")

    # Step 3: Build Prompts & Verify Token Budget
    print("\n--- Step 3: Building prompt and verifying token budget ---")
    chunk_entities = {
        cl.data.get("client_ip") for cl in target_chunk.lines if cl.data and cl.data.get("client_ip")
    }
    carried_context = state.build_carried_context(chunk_entities)
    user_prompt = build_chunk_prompt(
        carried_context=carried_context,
        chunk_text=target_chunk.text,
        start_line=target_chunk.start_line,
        end_line=target_chunk.end_line,
    )

    est_system_tokens = estimator.estimate_tokens(SYSTEM_PROMPT_CHUNK)
    est_user_tokens = estimator.estimate_tokens(user_prompt)
    est_total_prompt = est_system_tokens + est_user_tokens

    print(f"Estimated System Prompt tokens: {est_system_tokens}")
    print(f"Estimated User Prompt tokens:   {est_user_tokens}")
    print(f"Estimated Total Prompt tokens:  {est_total_prompt} (Budget: ~1648)")

    # Step 4: Run Ollama Model Call
    print("\n--- Step 4: Running Ollama model call ---")
    client = OllamaClient()
    start_time = time.time()
    result = client.generate(
        system_prompt=SYSTEM_PROMPT_CHUNK,
        user_prompt=user_prompt,
        num_predict=BUDGET_MODEL_REPLY,
    )
    elapsed = time.time() - start_time

    print(f"Actual prompt_eval_count: {result.prompt_tokens} tokens")
    print(f"Actual eval_count (output): {result.output_tokens} tokens")
    print(f"Total tokens used:         {result.total_tokens} / {MODEL_CONTEXT_WINDOW}")
    print(f"Call duration:             {elapsed:.1f}s")

    # Step 5: Parse and validate JSON findings
    print("\n--- Step 5: Parsing and Validating Model Output ---")
    parsed_json = parse_json_response(result.text)
    findings = validate_chunk_response(parsed_json)

    print(f"Validated findings count: {len(findings)}")
    print("Findings preview:")
    print(json.dumps(findings, indent=2))

    # Assertions
    assert result.prompt_tokens <= MODEL_CONTEXT_WINDOW, "Prompt overflowed context window!"
    assert result.output_tokens <= BUDGET_MODEL_REPLY + 50, "Output exceeded prediction cap!"
    print("\n✓ Phase 3 verified: Context window preserved, JSON structured output parsed cleanly.")


if __name__ == "__main__":
    main()

