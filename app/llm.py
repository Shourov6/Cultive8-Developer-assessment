"""
llm.py - Ollama client with timeout, retries, token tracking, and JSON mode.

This module owns ALL communication with the local Ollama model.
Every call enforces num_ctx=2048 and num_predict cap, tracks token usage,
and returns structured results.

Key design decisions:
  - Synchronous httpx calls (we run one model call at a time anyway).
  - think=false to avoid wasting tokens on chain-of-thought.
  - format="json" to force JSON output from the model.
  - All calls include num_ctx, num_predict, and num_thread in options.
"""

import time
import json
import logging
import httpx

from app.config import (
    OLLAMA_BASE_URL,
    MODEL_NAME,
    MODEL_CONTEXT_WINDOW,
    MODEL_NUM_THREADS,
    BUDGET_MODEL_REPLY,
    OLLAMA_TIMEOUT_SECONDS,
    OLLAMA_MAX_RETRIES,
    OLLAMA_RETRY_BACKOFF_BASE,
)

logger = logging.getLogger(__name__)


class OllamaError(Exception):
    """Raised when Ollama is unreachable or returns an error."""
    pass


class OllamaClient:
    """
    Thin wrapper around Ollama's /api/generate endpoint.

    Usage:
        client = OllamaClient()
        result = client.generate(system_prompt, user_prompt)
        # result is an OllamaResult with .text, .prompt_tokens, .output_tokens, etc.
    """

    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        model: str = MODEL_NAME,
        timeout: int = OLLAMA_TIMEOUT_SECONDS,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.generate_url = f"{self.base_url}/api/generate"
        self.tags_url = f"{self.base_url}/api/tags"

    # ------------------------------------------------------------------
    # Health / model listing
    # ------------------------------------------------------------------
    def check_health(self) -> dict:
        """
        Verify Ollama is reachable and return available models.
        Raises OllamaError if not reachable.
        """
        try:
            resp = httpx.get(self.tags_url, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except httpx.ConnectError:
            raise OllamaError(
                f"Cannot connect to Ollama at {self.base_url}. "
                "Is Ollama running?  Start it with: ollama serve"
            )
        except Exception as e:
            raise OllamaError(f"Ollama health check failed: {e}")

    def list_models(self) -> list[str]:
        """Return names of locally available models."""
        data = self.check_health()
        return [m["name"] for m in data.get("models", [])]

    # ------------------------------------------------------------------
    # Core generate call
    # ------------------------------------------------------------------
    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        num_predict: int = BUDGET_MODEL_REPLY,
        temperature: float = 0.3,
        retries: int = OLLAMA_MAX_RETRIES,
    ) -> "OllamaResult":
        """
        Send a prompt to the model and return the parsed result.

        Enforces:
          - num_ctx = 2048 (hard limit)
          - num_predict = capped output tokens
          - num_thread = 2 (CPU constraint)
          - format = "json" (structured output)
          - think = false (no chain-of-thought waste)
          - stream = false (we want the full response at once)

        Retries with exponential backoff on transient failures.
        """
        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "stream": False,
            "format": "json",
            "think": False,
            "options": {
                "num_ctx": MODEL_CONTEXT_WINDOW,
                "num_predict": num_predict,
                "num_thread": MODEL_NUM_THREADS,
                "temperature": temperature,
            },
        }

        last_error = None
        for attempt in range(1, retries + 1):
            try:
                logger.info(
                    "Ollama call attempt %d/%d  model=%s  num_ctx=%d  num_predict=%d",
                    attempt, retries, self.model,
                    MODEL_CONTEXT_WINDOW, num_predict,
                )
                start = time.time()

                resp = httpx.post(
                    self.generate_url,
                    json=payload,
                    timeout=self.timeout,
                )
                elapsed = time.time() - start
                resp.raise_for_status()

                data = resp.json()
                result = OllamaResult(data, elapsed)

                logger.info(
                    "Ollama response: prompt_tokens=%d  output_tokens=%d  "
                    "total_tokens=%d  elapsed=%.1fs",
                    result.prompt_tokens, result.output_tokens,
                    result.total_tokens, result.elapsed_seconds,
                )

                # Warn if we got close to or exceeded the context limit
                if result.prompt_tokens > MODEL_CONTEXT_WINDOW:
                    logger.warning(
                        "OVERFLOW: prompt_eval_count=%d exceeds num_ctx=%d!",
                        result.prompt_tokens, MODEL_CONTEXT_WINDOW,
                    )

                return result

            except httpx.ConnectError:
                raise OllamaError(
                    f"Cannot connect to Ollama at {self.base_url}. "
                    "Is it running?"
                )
            except httpx.TimeoutException:
                last_error = f"Ollama call timed out after {self.timeout}s"
                logger.warning(
                    "Attempt %d timed out (limit %ds)", attempt, self.timeout
                )
            except httpx.HTTPStatusError as e:
                last_error = f"Ollama HTTP error: {e.response.status_code}"
                logger.warning("Attempt %d HTTP error: %s", attempt, last_error)
            except Exception as e:
                last_error = str(e)
                logger.warning("Attempt %d failed: %s", attempt, last_error)

            # Exponential backoff before retry
            if attempt < retries:
                wait = OLLAMA_RETRY_BACKOFF_BASE ** attempt
                logger.info("Retrying in %ds...", wait)
                time.sleep(wait)

        raise OllamaError(
            f"Ollama call failed after {retries} attempts. Last error: {last_error}"
        )


class OllamaResult:
    """
    Parsed response from a single Ollama /api/generate call.

    Attributes:
        text:            Raw response string from the model.
        prompt_tokens:   Number of tokens the prompt consumed (prompt_eval_count).
        output_tokens:   Number of tokens the model generated (eval_count).
        total_tokens:    prompt_tokens + output_tokens.
        elapsed_seconds: Wall-clock time for the HTTP call.
        raw:             Full JSON response dict from Ollama.
    """

    def __init__(self, data: dict, elapsed: float):
        self.raw = data
        self.text = data.get("response", "")
        self.prompt_tokens = data.get("prompt_eval_count", 0)
        self.output_tokens = data.get("eval_count", 0)
        self.total_tokens = self.prompt_tokens + self.output_tokens
        self.elapsed_seconds = elapsed

    def __repr__(self):
        return (
            f"OllamaResult(prompt_tokens={self.prompt_tokens}, "
            f"output_tokens={self.output_tokens}, "
            f"elapsed={self.elapsed_seconds:.1f}s)"
        )

