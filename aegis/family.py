"""Name the attack family of a flagged window from a memory of known incidents.

Development tests (scripts/typing_experiment.py, research report
reports/Attack typing accuracy improvement.md) showed:
* a 3-nearest-neighbour vote over the window aggregates beat Random Forests,
  learned metrics and richer "behavioural" features — each day-file holds a
  different attack tool, and detailed features learn the tool, not the family;
* the language model added errors when it chose the family, so it now only
  explains the family this vote picks;
* naming a never-seen attack tool is capped by the data (42.6% on development
  windows), but naming a repeat of an incident an analyst already confirmed is
  near-perfect (98.5%).

So the family comes from an incident memory:
* bootstrap — labelled attack windows from the *other* usable day-files
  (the day being judged is never used; Infiltration days are excluded);
* confirmed — incidents an analyst approved in earlier reviews
  (data/incident_memory.jsonl), so the system learns from its reviewers.
"""

import hashlib
import json
from datetime import datetime, timezone
from functools import lru_cache

import joblib
import numpy as np

from . import config, data
from .evaluation import expected_attack_type

K = 3
GUARD_ROWS = 5_000  # benchmark memory: confirmed incidents end this many rows before the judged window
SAMPLES_PER_FILE = 1_500
MAX_PER_FILE = 150
SEED = 11

# Coarse groups: reported alongside the family, since e.g. DoS vs DDoS cannot be
# told apart reliably without source addresses, which the dataset lacks.
GROUPS = {
    "DDoS": "Volumetric flood",
    "DoS": "Volumetric flood",
    "Brute Force": "Login attack",
    "Web Attack": "Web exploitation",
    "Botnet": "Command and control",
    "Infiltration": "Intrusion",
    "Port Scan": "Reconnaissance",
    "Unknown": "Unknown",
}


def labelled_windows(dataset_id: str, window_size: int, seed: int = SEED, per_file: int = MAX_PER_FILE, ablate_tcp_window: bool = False) -> list[dict]:
    """Attack windows (at least half attack flows) from one day-file, with their family."""
    frame = data._frame(dataset_id)
    rng = np.random.default_rng(seed)
    out = []
    for start in rng.integers(0, max(1, len(frame) - window_size), SAMPLES_PER_FILE):
        chunk = frame.iloc[int(start) : int(start) + window_size]
        truth = data.ground_truth(chunk)
        if truth["is_attack"]:
            labels = {k: v for k, v in truth["label_counts"].items() if k != "Benign"}
            out.append({
                "features": data.summarize(chunk, ablate_tcp_window),
                "family": expected_attack_type(max(labels, key=labels.get)),
                "day": dataset_id,
                "row_start": int(start),
                "source": "known incident",
            })
            if len(out) >= per_file:
                break
    return out


@lru_cache(maxsize=32)
def bootstrap(files: tuple[str, ...], window_size: int, ablate_tcp_window: bool = False) -> list[dict]:
    key = hashlib.sha256(json.dumps([files, window_size, ablate_tcp_window, SAMPLES_PER_FILE, MAX_PER_FILE, "memory-v1"]).encode()).hexdigest()[:16]
    path = config.MODELS_DIR / f"memory-{key}.joblib"
    if path.exists():
        return joblib.load(path)
    entries = [e for f in files for e in labelled_windows(f, window_size, ablate_tcp_window=ablate_tcp_window)]
    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(entries, path)
    return entries


# --- analyst-confirmed incidents ------------------------------------------------

def confirmed() -> list[dict]:
    if not config.MEMORY_FILE.exists():
        return []
    with config.MEMORY_FILE.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def confirm(features: dict, family: str, run_id: str, window: int, by: str) -> dict:
    """Remember an analyst-confirmed incident so later windows like it get the same family."""
    entry = {
        "features": features,
        "family": family,
        "day": f"run {run_id}",
        "window": window,
        "source": "confirmed incident",
        "confirmed_by": by,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    config.MEMORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with config.MEMORY_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


# --- the vote --------------------------------------------------------------------

class FamilyVote:
    def __init__(self, entries: list[dict]):
        from sklearn.preprocessing import StandardScaler

        if not entries:
            raise ValueError("The incident memory is empty.")
        self.names = sorted(entries[0]["features"])
        usable = [e for e in entries if all(n in e["features"] for n in self.names)]
        self.entries = usable
        matrix = np.array([[e["features"][n] for n in self.names] for e in usable], float)
        # Scaled on attack windows (not on normal traffic): we compare attacks with attacks.
        self.scaler = StandardScaler().fit(matrix)
        self.matrix = self.scaler.transform(matrix)

    def vote(self, features: dict) -> dict:
        row = self.scaler.transform(np.array([[features[n] for n in self.names]], float))
        distances = np.linalg.norm(self.matrix - row, axis=1)
        nearest = np.argsort(distances)[:K]
        families = [self.entries[i]["family"] for i in nearest]
        counts = {f: families.count(f) for f in families}
        # Majority; ties go to the nearest neighbour's family.
        best = max(counts, key=lambda f: (counts[f], -families.index(f)))
        return {
            "family": best,
            "group": GROUPS.get(best, "Unknown"),
            "votes": f"{counts[best]}/{K}",
            "agreement": round(counts[best] / K, 2),
            "neighbours": [
                {
                    "family": self.entries[i]["family"],
                    "source": self.entries[i]["source"],
                    "day": str(self.entries[i]["day"]).split("_")[0],
                    "distance": round(float(distances[i]), 2),
                }
                for i in nearest
            ],
        }


def voter(test_dataset: str, window_size: int, extra: list[dict] | None = None, ablate_tcp_window: bool = False) -> FamilyVote:
    """Memory = labelled incidents from other days + analyst-confirmed incidents (+ `extra`)."""
    from .anomaly import usable_files

    entries = list(bootstrap(tuple(usable_files(exclude=test_dataset)), window_size, ablate_tcp_window))
    entries += confirmed() + (extra or [])
    return FamilyVote(entries)
