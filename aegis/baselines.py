"""Classical baselines, scored on exactly the windows the agents saw.

* random_forest — a flow-level RandomForest trained on *other* day-files
  (the test day is always left out, Infiltration days are never used), on a
  class-balanced sample of each file. A window counts as an attack when at
  least `label_threshold` of its flows are predicted attack — the same rule as
  the ground truth — so its verdict is directly comparable with the pipeline.
* tcp_window_rule — the single-feature shortcut "unique TCP window ratio
  <= 0.05". If this alone matches the agents, the detector is mostly reading a
  testbed artefact.

Trained models are cached in data/models/, keyed by their training files.
"""

import hashlib
import json
from functools import lru_cache

import joblib
import numpy as np
import pandas as pd

from . import config, data

SAMPLE_PER_CLASS = 10_000  # flows per class per training file
N_TREES = 100
SEED = 7


def training_files(test_dataset: str) -> list[str]:
    return [
        d["dataset_id"]
        for d in data.list_datasets()
        if d["dataset_id"] != test_dataset and not d["excluded_by_default"]
    ]


def _matrix(frame: pd.DataFrame, ablate_tcp_window: bool) -> np.ndarray:
    columns = [c for c in data.FLOW_FEATURES if not (ablate_tcp_window and c == data.TCP_WINDOW)]
    x = frame[columns].astype("float64").replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return x.clip(-1e12, 1e12).to_numpy()


@lru_cache(maxsize=8)
def model(files: tuple[str, ...], ablate_tcp_window: bool = False):
    from sklearn.ensemble import RandomForestClassifier

    key = hashlib.sha256(json.dumps([files, ablate_tcp_window, SAMPLE_PER_CLASS, N_TREES]).encode()).hexdigest()[:16]
    path = config.MODELS_DIR / f"rf-{key}.joblib"
    if path.exists():
        return joblib.load(path)

    parts = []
    for dataset_id in files:
        frame = data._frame(dataset_id)
        attack = frame["Label"] != "Benign"
        for mask in (attack, ~attack):
            subset = frame[mask]
            parts.append(subset.sample(min(len(subset), SAMPLE_PER_CLASS), random_state=SEED))
    train = pd.concat(parts, ignore_index=True)
    clf = RandomForestClassifier(n_estimators=N_TREES, class_weight="balanced", n_jobs=-1, random_state=SEED)
    clf.fit(_matrix(train, ablate_tcp_window), (train["Label"] != "Benign").to_numpy())
    bundle = {
        "classifier": clf,
        "trained_on": list(files),
        "training_flows": int(len(train)),
        "ablate_tcp_window": ablate_tcp_window,
    }
    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)
    return bundle


def score(test_dataset: str, windows: list[dict], label_threshold: float = 0.5, ablate_tcp_window: bool = False) -> dict:
    """Baseline verdicts for windows loaded with include_flows=True."""
    rule = [
        {"attack": w["features"].get("unique_tcp_window_ratio", 1.0) <= 0.05} for w in windows
    ]
    files = training_files(test_dataset)
    if not files:
        return {
            "random_forest": {"available": False, "reason": "No other usable day-files to train on."},
            "tcp_window_rule": {"available": "unique_tcp_window_ratio" in windows[0]["features"], "windows": rule},
        }
    bundle = model(tuple(files), ablate_tcp_window)
    clf = bundle["classifier"]
    verdicts = []
    for w in windows:
        predicted = clf.predict(_matrix(w["flows"], ablate_tcp_window))
        share = round(float(predicted.mean()), 3)
        verdicts.append({"attack": share >= label_threshold, "attack_share": share})
    return {
        "random_forest": {
            "available": True,
            "trained_on": bundle["trained_on"],
            "training_flows": bundle["training_flows"],
            "windows": verdicts,
        },
        "tcp_window_rule": {"available": "unique_tcp_window_ratio" in windows[0]["features"], "windows": rule},
    }
