"""Development tuning of the hybrid detector (never uses benchmark seeds).

    python scripts/detector_tuning.py

Judged windows come from development seeds 21 and 22 on every usable
day-file; the normal-traffic baseline is learned exactly as in production.
Compared:
  1. false-alarm budget x one-class SVM nu x gamma (grid);
  2. extra behavioural features (payload size, inter-arrival time, byte ratio);
  3. confirmed-incident memory for detection: attack windows an analyst
     confirmed earlier in the same capture (ending >= 5,000 rows before the
     judged window) are added to the normal baseline as labelled examples, and
     a nearest-neighbour vote overrides the detector when a confirmed
     incident is close.
Scores: MCC, recall and false-alarm rate pooled over all days and both seeds.
"""

import itertools
import sys
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis import anomaly, data, family  # noqa: E402
from aegis.agents import monitoring_score  # noqa: E402
from aegis.evaluation import confusion  # noqa: E402

DEV_SEEDS = (21, 22)
PER_FILE = 50
GATE = anomaly.HOMOGENEITY_GATE
EXTRA = {
    "Fwd Packet Length Mean": "fwd_payload_median",
    "Bwd Packet Length Mean": "bwd_payload_median",
    "Flow IAT Mean": "iat_median",
    "Fwd Packets Length Total": "fwd_bytes_median",
    "ACK Flag Count": "ack_share",
}


@lru_cache(maxsize=12)
def extra_frame(dataset_id: str) -> pd.DataFrame:
    return pd.read_parquet(data._path(dataset_id), columns=list(EXTRA))


def extra_features(dataset_id: str, start: int, size: int = 100) -> dict:
    chunk = extra_frame(dataset_id).iloc[start : start + size]
    out = {}
    for column, name in EXTRA.items():
        values = chunk[column].astype(float)
        out[name] = float((values > 0).mean()) if name == "ack_share" else float(np.log1p(values.clip(lower=0)).median())
    return out


def baseline(dataset_id, judged):
    rng = np.random.default_rng(anomaly.SEED)
    blocked = [(w["row_start"] - anomaly.GUARD_ROWS - 100, w["row_end"] + anomaly.GUARD_ROWS) for w in judged]
    frame = data._frame(dataset_id)
    out = []
    for start in rng.integers(0, len(frame) - 100, anomaly.SAME_NETWORK_SAMPLES):
        start = int(start)
        if any(lo <= start <= hi for lo, hi in blocked):
            continue
        chunk = frame.iloc[start : start + 100]
        if data.ground_truth(chunk)["attack_share"] == 0:
            out.append({"features": data.summarize(chunk, True), "row_start": start})
            if len(out) >= anomaly.MAX_BENIGN:
                break
    return out


def build_days():
    """Per day and seed: judged windows, normal baseline and confirmed incidents (with extra features)."""
    days = []
    for dataset_id in anomaly.usable_files():
        confirmed = family.labelled_windows(dataset_id, 100, ablate_tcp_window=True)
        for e in confirmed:
            e["extra"] = extra_features(dataset_id, e["row_start"])
        for seed in DEV_SEEDS:
            judged = data.load_windows(dataset_id, PER_FILE, 100, seed=seed, ablate_tcp_window=True)
            normal = baseline(dataset_id, judged)
            for w in judged:
                w["extra"] = extra_features(dataset_id, w["row_start"])
            for n in normal:
                n["extra"] = extra_features(dataset_id, n["row_start"])
            days.append({"day": dataset_id, "judged": judged, "normal": normal, "confirmed": confirmed})
            print(f"  {dataset_id.split('_')[0]} seed {seed}: {len(judged)} judged, {len(normal)} normal", flush=True)
    return days


def vectors(items, keys, extra):
    return np.array([[it["features"][k] for k in keys] + ([it["extra"][k] for k in sorted(EXTRA.values())] if extra else []) for it in items], float)


def run(days, budget=0.05, nu=0.05, gamma="scale", extra=False, memory=None):
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import OneClassSVM

    truth, pred = [], []
    for d in days:
        if len(d["normal"]) < 30:
            continue
        keys = sorted(k for k in d["normal"][0]["features"] if k != "flows")
        x = vectors(d["normal"], keys, extra)
        rng = np.random.default_rng(7)
        order = rng.permutation(len(x))
        train, held = x[order[: int(len(x) * 0.8)]], x[order[int(len(x) * 0.8):]]
        sc = StandardScaler().fit(train)
        model = OneClassSVM(nu=nu, gamma=gamma).fit(sc.transform(train))
        limit = np.quantile(-model.score_samples(sc.transform(held)), 1 - budget)
        t = vectors(d["judged"], keys, extra)
        flagged = (-model.score_samples(sc.transform(t)) > limit) & np.array(
            [monitoring_score(w["features"]) >= GATE for w in d["judged"]])
        if memory:
            normal_scaled = sc.transform(x)
            for i, w in enumerate(d["judged"]):
                earlier = [c for c in d["confirmed"] if c["row_start"] <= w["row_start"] - family.GUARD_ROWS]
                if not earlier:
                    continue
                mem = sc.transform(vectors(earlier, keys, extra))
                row = sc.transform(t[i : i + 1])
                d_attack = np.linalg.norm(mem - row, axis=1).min()
                d_normal = np.linalg.norm(normal_scaled - row, axis=1).min()
                if memory == "override":
                    flagged[i] = d_attack < d_normal  # closer to a confirmed attack than to any normal window
                elif memory == "add":
                    flagged[i] = flagged[i] or d_attack < 0.5 * d_normal
        truth += [w["truth"]["is_attack"] for w in d["judged"]]
        pred += list(flagged)
    return confusion(truth, pred)


def show(label, m):
    print(f"{label:<62} MCC {m['mcc']:.3f}  recall {m['recall']:.3f}  FPR {m['false_positive_rate']:.3f}  F1 {m['f1']:.3f}", flush=True)


def main() -> None:
    print("Building development windows…", flush=True)
    days = build_days()
    print()
    current = run(days)
    show("current (budget 0.05, nu 0.05, gamma scale)", current)

    print("\n1. Grid: budget x nu x gamma")
    grid = []
    for budget, nu, gamma in itertools.product((0.02, 0.05, 0.08, 0.12), (0.01, 0.05, 0.1, 0.2), ("scale", 0.02, 0.05, 0.1)):
        grid.append(((budget, nu, gamma), run(days, budget, nu, gamma)))
    grid.sort(key=lambda g: -g[1]["mcc"])
    for (budget, nu, gamma), m in grid[:8]:
        show(f"   budget {budget}, nu {nu}, gamma {gamma}", m)
    best = grid[0][0]

    print("\n2. Extra behavioural features")
    show("   current settings + extra features", run(days, extra=True))
    show(f"   best grid {best} + extra features", run(days, *best, extra=True))

    print("\n3. Confirmed-incident memory for detection")
    for cfg_label, cfg in (("current settings", (0.05, 0.05, "scale")), (f"best grid {best}", best)):
        for mode in ("add", "override"):
            show(f"   {cfg_label} + memory ({mode})", run(days, *cfg, memory=mode))


if __name__ == "__main__":
    main()
