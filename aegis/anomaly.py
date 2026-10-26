"""Benign-trained anomaly detector for the hybrid pipeline.

The detector learns what *normal* traffic windows look like and flags windows
that do not fit, so it needs no examples of the attack it is facing (a model
trained on known attacks missed the new attack on each unseen day).

Two ways to learn "normal":
* same-network (default) — like a deployment that learns its own network:
  fully benign windows from the same capture, never overlapping (±1,000 rows)
  the windows being judged, topped up from other day-files if too few exist;
* cross-day (strict) — fully benign windows from the *other* day-files only.
Infiltration day-files are never used. Labels only decide which training
windows count as normal; the detector never sees an attack.

Model: standardised window features → IsolationForest. Threshold: a fixed
false-alarm budget — the 95th percentile of anomaly scores on held-out normal
windows — chosen in advance, not tuned on attacks. Confidence is 100 × the
share of held-out normal windows that look less unusual (an empirical p-value),
not a model's self-report.

Evidence for the explaining agent: the features that deviate most from normal,
and the most similar known incidents from other day-files (retrieval over
labelled attack windows).
"""

import hashlib
import json
from functools import lru_cache

import joblib
import numpy as np

from . import config, data
from .evaluation import expected_attack_type

FALSE_ALARM_BUDGET = 0.05
GUARD_ROWS = 1_000  # keep training windows this far from any judged window
SAMPLES_PER_FILE = 600
SAME_NETWORK_SAMPLES = 4_000
MAX_BENIGN = 400
MIN_BENIGN = 150
MAX_INCIDENTS = 120
NEIGHBOURS = 5
SEED = 7
BASELINES = ("same-network", "cross-day")


def _keys(sample: dict) -> list[str]:
    return sorted(k for k in sample if k != "flows")


def usable_files(exclude: str | None = None) -> list[str]:
    return [
        d["dataset_id"]
        for d in data.list_datasets()
        if d["dataset_id"] != exclude and not d["excluded_by_default"]
    ]


def _sample(dataset_id: str, window_size: int, ablate: bool, rng, tries: int, blocked=(), want_attacks=False):
    """Fully benign windows (and, optionally, labelled attack windows) from one day-file."""
    frame = data._frame(dataset_id)
    benign, attacks = [], []
    for start in rng.integers(0, max(1, len(frame) - window_size), tries):
        start = int(start)
        if any(lo <= start <= hi for lo, hi in blocked):
            continue
        chunk = frame.iloc[start : start + window_size]
        truth = data.ground_truth(chunk)
        if truth["attack_share"] == 0 and len(benign) < MAX_BENIGN:
            benign.append(data.summarize(chunk, ablate))
        elif want_attacks and truth["is_attack"] and len(attacks) < MAX_INCIDENTS:
            labels = {k: v for k, v in truth["label_counts"].items() if k != "Benign"}
            attacks.append((data.summarize(chunk, ablate), expected_attack_type(max(labels, key=labels.get)), dataset_id))
        if len(benign) >= MAX_BENIGN and (not want_attacks or len(attacks) >= MAX_INCIDENTS):
            break
    return benign, attacks


@lru_cache(maxsize=16)
def _other_days(files: tuple[str, ...], window_size: int, ablate: bool) -> dict:
    """Benign windows and labelled incidents from other day-files (cached on disk)."""
    key = hashlib.sha256(json.dumps([files, window_size, ablate, SAMPLES_PER_FILE, "v3"]).encode()).hexdigest()[:16]
    path = config.MODELS_DIR / f"otherdays-{key}.joblib"
    if path.exists():
        return joblib.load(path)
    rng = np.random.default_rng(SEED)
    benign, incidents = [], []
    for dataset_id in files:
        b, a = _sample(dataset_id, window_size, ablate, rng, SAMPLES_PER_FILE, want_attacks=True)
        benign += b
        incidents += a
    result = {"benign": benign, "incidents": incidents}
    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(result, path)
    return result


def _fit(benign: list[dict], incidents: list, keys: list[str]) -> dict:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    rng = np.random.default_rng(SEED)
    x = np.array([[f[k] for k in keys] for f in benign], float)
    order = rng.permutation(len(x))
    split = int(len(x) * 0.8)
    train, held_out = x[order[:split]], x[order[split:]]
    scaler = StandardScaler().fit(train)
    forest = IsolationForest(n_estimators=200, random_state=SEED).fit(scaler.transform(train))
    held_scores = np.sort(-forest.score_samples(scaler.transform(held_out)))
    return {
        "keys": keys,
        "scaler": scaler,
        "forest": forest,
        "threshold": float(np.quantile(held_scores, 1 - FALSE_ALARM_BUDGET)),
        "benign_median_score": float(np.median(held_scores)),
        "held_out_scores": held_scores,
        "median": np.median(x, axis=0),
        "iqr": np.maximum(np.subtract(*np.percentile(x, [75, 25], axis=0)), 1e-6),
        "incident_vectors": scaler.transform(np.array([[f[k] for k in keys] for f, _, _ in incidents], float))
        if incidents
        else np.empty((0, len(keys))),
        "incident_labels": [(family, day) for _, family, day in incidents],
    }


def fit(test_dataset: str, windows: list[dict], window_size: int, baseline: str = "same-network", ablate_tcp_window: bool = False) -> tuple[dict, dict]:
    if baseline not in BASELINES:
        raise ValueError(f"Unknown baseline: {baseline}")
    files = usable_files(exclude=test_dataset)
    other = _other_days(tuple(files), window_size, ablate_tcp_window) if files else {"benign": [], "incidents": []}
    benign, sources = [], []
    if baseline == "same-network":
        blocked = [(w["row_start"] - GUARD_ROWS - window_size, w["row_end"] + GUARD_ROWS) for w in windows]
        rng = np.random.default_rng(SEED)
        local, _ = _sample(test_dataset, window_size, ablate_tcp_window, rng, SAME_NETWORK_SAMPLES, blocked)
        benign += local
        sources.append(f"{len(local)} normal windows from this capture (not overlapping judged windows)")
    if len(benign) < MIN_BENIGN or baseline == "cross-day":
        extra = other["benign"] if baseline == "cross-day" else other["benign"][: MAX_BENIGN * 2]
        benign += extra
        sources.append(f"{len(extra)} normal windows from {len(files)} other day-files")
    if len(benign) < 20:
        raise ValueError("Not enough normal traffic windows to learn a baseline.")
    bundle = _fit(benign, other["incidents"], _keys(benign[0]))
    info = {
        "method": "isolation-forest (benign-trained)",
        "baseline": baseline,
        "normal_windows": len(benign),
        "sources": sources,
        "known_incidents": len(other["incidents"]),
        "threshold": round(bundle["threshold"], 4),
        "false_alarm_budget": FALSE_ALARM_BUDGET,
    }
    return bundle, info


def _describe(name: str, value: float, median: float, z: float) -> str:
    direction = "above" if value > median else "below"
    return f"{name} = {value:g} ({abs(z):.1f} IQR {direction} normal {median:g})"


def evidence(bundle: dict, features: dict) -> dict:
    """Label-free verdict and evidence for one window's features."""
    keys = bundle["keys"]
    raw = np.array([features[k] for k in keys], float)
    scaled = bundle["scaler"].transform(raw.reshape(1, -1))
    score = float(-bundle["forest"].score_samples(scaled)[0])
    held = bundle["held_out_scores"]
    confidence = int(round(100 * np.searchsorted(held, score, side="left") / (len(held) + 1)))
    threshold, middle = bundle["threshold"], bundle["benign_median_score"]
    # Same 0–1 scale as the monitoring gate, with the detector threshold at 0.6.
    normalised = float(np.clip(0.6 * (score - middle) / max(threshold - middle, 1e-9), 0, 1))

    z = (raw - bundle["median"]) / bundle["iqr"]
    top = np.argsort(-np.abs(z))[:3]
    deviations = [_describe(keys[i], raw[i], float(bundle["median"][i]), float(z[i])) for i in top if abs(z[i]) >= 1]

    similar = []
    if len(bundle["incident_vectors"]):
        distances = np.linalg.norm(bundle["incident_vectors"] - scaled, axis=1)
        for i in np.argsort(distances)[:NEIGHBOURS]:
            family, day = bundle["incident_labels"][i]
            similar.append({"family": family, "day": day.split("_")[0], "distance": round(float(distances[i]), 2)})
    return {
        "method": "isolation-forest (benign-trained)",
        "anomalous": score > threshold,
        "anomaly_score": round(score, 4),
        "threshold": round(threshold, 4),
        "score": round(normalised, 3),
        "confidence": min(confidence, 99),
        "deviations": deviations,
        "similar_incidents": similar,
    }


def score(test_dataset: str, windows: list[dict], window_size: int, baseline: str = "same-network", ablate_tcp_window: bool = False) -> tuple[list[dict], dict]:
    bundle, info = fit(test_dataset, windows, window_size, baseline, ablate_tcp_window)
    return [evidence(bundle, w["features"]) for w in windows], info
