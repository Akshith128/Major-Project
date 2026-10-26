import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

from aegis.llm import LLMUnavailable

DATASET = "synthetic.parquet"


def make_dataset(directory: Path, benign: int = 300, attack: int = 300) -> str:
    """Benign flows are varied; attack flows repeat one TCP signature."""
    rng = np.random.default_rng(7)

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
        directory / DATASET
    )
    return DATASET


class FakeLLM:
    provider = "gemini"
    model = "fake"
    configured = True

    def __init__(self, detection=None, fail=False):
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
        if "response agent" in prompt:
            return {"actions": ["Rate-limit the service", "Block sources"], "rationale": "Contain flood."}
        return self.detection


def temp_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="aegis-test-"))
