import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

from unittest import mock

from aegis import baselines, config, data, keys
from aegis.llm import LLMUnavailable

DATASET = "synthetic.parquet"
ANALYST = {"username": "akshith", "name": "Akshith", "role": "analyst"}


def make_dataset(directory: Path, benign: int = 300, attack: int = 300, name: str = DATASET, seed: int = 7) -> str:
    """Benign flows are varied; attack flows repeat one TCP signature."""
    rng = np.random.default_rng(seed)

    def flows(n, attack_flows):
        return pd.DataFrame(
            {
                "Protocol": np.full(n, 6) if attack_flows else rng.choice([6, 17], n),
                "Flow Duration": rng.integers(1_000, 900_000, n),
                "Total Fwd Packets": np.full(n, 2) if attack_flows else rng.integers(1, 40, n),
                "Total Backward Packets": np.zeros(n, int) if attack_flows else rng.integers(0, 40, n),
                "Flow Bytes/s": rng.random(n) * 1e4,
                "Flow Packets/s": rng.random(n) * 1e3,
                "SYN Flag Count": np.zeros(n, int),
                "RST Flag Count": np.ones(n, int) if attack_flows else np.zeros(n, int),
                "FIN Flag Count": np.zeros(n, int),
                "PSH Flag Count": np.zeros(n, int),
                "Avg Packet Size": rng.random(n) * 500,
                "Init Fwd Win Bytes": np.full(n, 8192) if attack_flows else rng.integers(0, 65535, n),
                "Label": ["DDoS attacks-LOIC-HTTP" if attack_flows else "Benign"] * n,
            }
        )

    pd.concat([flows(benign, False), flows(attack, True)], ignore_index=True).to_parquet(
        directory / name
    )
    return name


def isolate(test) -> Path:
    """Point every file AEGIS writes (data, runs, keys, checkpoints, accounts) at a temp dir."""
    directory = temp_dir()
    for name, value in {
        "DATA_DIR": directory,
        "SECRETS_DIR": directory / "secrets",
        "CHECKPOINT_FILE": directory / "secrets" / "checkpoints.jsonl",
        "USERS_FILE": directory / "users.json",
        "CONTROL_FILE": directory / "control.json",
        "MODELS_DIR": directory / "models",
        "AUDIT_KEY": None,
        "AUTH_SECRET": None,
    }.items():
        patcher = mock.patch.object(config, name, value)
        patcher.start()
        test.addCleanup(patcher.stop)
    for cache in (data._frame, keys.load, baselines.model):
        cache.cache_clear()
        test.addCleanup(cache.cache_clear)
    return directory


class FakeLLM:
    provider = "gemini"
    model = "fake"
    configured = True
    last_meta: dict = {}

    def __init__(self, detection=None, fail=False, explanation=None):
        self.explanation = explanation or {"attack_type": "DDoS", "severity_hint": None, "explanation": "Flood of identical flows."}
        self.detection = detection or {
            "threat": True,
            "attack_type": "DDoS",
            "confidence": 92,
            "reasoning": "Repeated TCP signature.",
        }
        self.fail = fail
        self.prompts: list[str] = []

    def ask_json(self, prompt):
        self.prompts.append(prompt)
        if self.fail:
            raise LLMUnavailable("offline")
        self.last_meta = {"model_version": "fake-001", "latency_ms": 5, "tokens_in": 100, "tokens_out": 20}
        if "NOT to decide" in prompt:
            return self.explanation
        if "response agent" in prompt:
            return {"actions": ["Rate-limit the service", "Block sources"], "rationale": "Contain flood."}
        return self.detection


def temp_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="aegis-test-"))
