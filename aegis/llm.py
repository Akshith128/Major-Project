"""Gemini access for the reasoning agents.

Agents call `ask_json`; if Gemini is not configured or a call fails, they get
`LLMUnavailable` and fall back to their rule-based path, recording which
source produced each decision. After each successful call `last_meta` holds
what the decision record needs to be reproduced: the model version the API
actually served, temperature, latency and token counts.
"""

import json
import re
import time

from . import config

# Keep a slow model from stalling a run: after this, the agent falls back to rules.
TIMEOUT_MS = 25_000
ATTEMPTS = 2


class LLMUnavailable(RuntimeError):
    pass


class GeminiLLM:
    provider = "gemini"

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.model = model or config.GEMINI_MODEL
        self._api_key = api_key or config.GOOGLE_API_KEY
        self._client = None
        self.last_meta: dict = {}

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    def _get_client(self):
        if not self.configured:
            raise LLMUnavailable("GOOGLE_API_KEY is not set.")
        if self._client is None:
            from google import genai
            from google.genai import types

            self._client = genai.Client(
                api_key=self._api_key, http_options=types.HttpOptions(timeout=TIMEOUT_MS)
            )
        return self._client

    def ask_json(self, prompt: str) -> dict:
        from google.genai import types

        client = self._get_client()
        last_error: Exception | None = None
        for attempt in range(ATTEMPTS):
            try:
                started = time.perf_counter()
                response = client.models.generate_content(
                    model=self.model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json", temperature=config.GEMINI_TEMPERATURE
                    ),
                )
                usage = getattr(response, "usage_metadata", None)
                self.last_meta = {
                    "model_version": getattr(response, "model_version", None) or self.model,
                    "temperature": config.GEMINI_TEMPERATURE,
                    "latency_ms": round((time.perf_counter() - started) * 1000),
                    "tokens_in": getattr(usage, "prompt_token_count", None),
                    "tokens_out": getattr(usage, "candidates_token_count", None),
                    "attempts": attempt + 1,
                }
                return parse_json(response.text or "")
            except LLMUnavailable:
                raise
            except Exception as error:  # network, quota, server errors
                last_error = error
                message = str(error)
                if "429" in message or "quota" in message.lower():
                    raise LLMUnavailable("Gemini quota exceeded.") from error
                if attempt < ATTEMPTS - 1:
                    time.sleep(1)
        raise LLMUnavailable(f"Gemini request failed: {last_error}")


def parse_json(text: str) -> dict:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise LLMUnavailable("Gemini returned no JSON object.")
    try:
        value = json.loads(match.group(0))
    except json.JSONDecodeError as error:
        raise LLMUnavailable("Gemini returned malformed JSON.") from error
    if not isinstance(value, dict):
        raise LLMUnavailable("Gemini returned a non-object JSON value.")
    return value


class NoLLM:
    """Rules-only mode: every agent takes its deterministic path."""

    provider = "rules"
    model = None
    configured = False
    last_meta: dict = {}

    def ask_json(self, prompt: str) -> dict:
        raise LLMUnavailable("Rules-only mode.")
