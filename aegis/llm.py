"""Reasoning-model access for the agents: a local Ollama model, Groq or Gemini.

`make_llm()` returns the provider named by AEGIS_LLM_PROVIDER. Agents call
`ask_json`; if the model is not available or a call fails, they get
`LLMUnavailable` and fall back to their rule-based path, recording which
source produced each decision. After each successful call `last_meta` holds
what the decision record needs to be reproduced: the model version the API
actually served, temperature, latency and token counts.
"""

import json
import re
import time

import httpx

from . import config

LLM_SOURCES = ("ollama", "groq", "gemini")  # detection/response sources that mean "a reasoning model answered"

# Keep a slow model from stalling a run: after this, the agent falls back to rules.
TIMEOUT_MS = 25_000
ATTEMPTS = 2


class LLMUnavailable(RuntimeError):
    pass


class GeminiLLM:
    provider = "gemini"
    local = False

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.model = model or config.GEMINI_MODEL
        self._api_key = api_key or config.GOOGLE_API_KEY
        self._client = None
        self.last_meta: dict = {}

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    @property
    def note(self) -> str | None:
        return None if self._api_key else "GOOGLE_API_KEY is not set."

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

    def ask_json(self, prompt: str, schema: dict | None = None) -> dict:
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


class OllamaLLM:
    """A model served by Ollama on this machine: free, no quota, and no data leaves the PC."""

    provider = "ollama"
    local = True
    TIMEOUT_S = 180  # small models on a CPU can take a while per answer

    def __init__(self, url: str | None = None, model: str | None = None):
        self.url = (url or config.OLLAMA_URL).rstrip("/")
        self.model = model or config.OLLAMA_MODEL
        self.last_meta: dict = {}
        self.note: str | None = None

    @property
    def configured(self) -> bool:
        try:
            tags = httpx.get(f"{self.url}/api/tags", timeout=2).json()
        except (httpx.HTTPError, ValueError):
            self.note = f"Ollama is not running at {self.url}."
            return False
        names = {m.get("name") for m in tags.get("models", [])}
        if self.model in names or f"{self.model}:latest" in names:
            self.note = None
            return True
        self.note = f"Model {self.model} is not pulled. Run: ollama pull {self.model}"
        return False

    def ask_json(self, prompt: str, schema: dict | None = None) -> dict:
        body = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "format": schema or "json",  # a JSON Schema makes Ollama emit exactly that shape
            "stream": False,
            "options": {"temperature": config.LLM_TEMPERATURE, "seed": 7},
        }
        started = time.perf_counter()
        try:
            response = httpx.post(f"{self.url}/api/chat", json=body, timeout=self.TIMEOUT_S)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as error:
            raise LLMUnavailable(f"Ollama request failed: {error}") from error
        self.last_meta = {
            "model_version": data.get("model", self.model),
            "temperature": config.LLM_TEMPERATURE,
            "latency_ms": round((time.perf_counter() - started) * 1000),
            "tokens_in": data.get("prompt_eval_count"),
            "tokens_out": data.get("eval_count"),
            "attempts": 1,
        }
        return parse_json(data.get("message", {}).get("content", ""))


class GroqLLM:
    """Groq's hosted open models (OpenAI-compatible API, free tier with rate limits)."""

    provider = "groq"
    local = False
    URL = "https://api.groq.com/openai/v1/chat/completions"

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self._api_key = api_key or config.GROQ_API_KEY
        self.model = model or config.GROQ_MODEL
        self.last_meta: dict = {}
        self.note = None if self._api_key else "GROQ_API_KEY is not set."

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    def ask_json(self, prompt: str, schema: dict | None = None) -> dict:
        if not self._api_key:
            raise LLMUnavailable("GROQ_API_KEY is not set.")
        body = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": config.LLM_TEMPERATURE,
            "response_format": {"type": "json_object"},
        }
        started = time.perf_counter()
        try:
            response = httpx.post(
                self.URL, json=body, timeout=TIMEOUT_MS / 1000, headers={"Authorization": f"Bearer {self._api_key}"}
            )
        except httpx.HTTPError as error:
            raise LLMUnavailable(f"Groq request failed: {error}") from error
        if response.status_code == 429:
            raise LLMUnavailable("Groq rate limit reached.")
        if response.status_code >= 400:
            raise LLMUnavailable(f"Groq request failed (HTTP {response.status_code}).")
        data = response.json()
        usage = data.get("usage", {})
        self.last_meta = {
            "model_version": data.get("model", self.model),
            "temperature": config.LLM_TEMPERATURE,
            "latency_ms": round((time.perf_counter() - started) * 1000),
            "tokens_in": usage.get("prompt_tokens"),
            "tokens_out": usage.get("completion_tokens"),
            "attempts": 1,
        }
        return parse_json(data["choices"][0]["message"]["content"] or "")


def make_llm(provider: str | None = None):
    """The reasoning model named by AEGIS_LLM_PROVIDER (ollama, groq or gemini)."""
    name = (provider or config.LLM_PROVIDER).lower()
    if name == "ollama":
        return OllamaLLM()
    if name == "groq":
        return GroqLLM()
    if name == "gemini":
        return GeminiLLM()
    raise ValueError(f"Unknown AEGIS_LLM_PROVIDER: {name} (use ollama, groq or gemini)")


class NoLLM:
    """Rules-only mode: every agent takes its deterministic path."""

    provider = "rules"
    model = None
    configured = False
    last_meta: dict = {}

    def ask_json(self, prompt: str, schema: dict | None = None) -> dict:
        raise LLMUnavailable("Rules-only mode.")
