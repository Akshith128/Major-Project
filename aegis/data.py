"""CIC-IDS2018 flow data → fixed-size traffic windows.

Each window carries two strictly separated parts:
  * `features` — aggregate traffic statistics the agents may see;
  * `truth`    — label counts, used ONLY by evaluation after the run.
"""

from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from . import config

COLUMNS = [
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "RST Flag Count",
    "FIN Flag Count",
    "PSH Flag Count",
    "Avg Packet Size",
    "Init Fwd Win Bytes",
    "Label",
]

SIGNATURE = ["Protocol", "Init Fwd Win Bytes", "Total Fwd Packets", "Total Backward Packets"]
# The TCP initial window is a suspected testbed shortcut (one attack tool, one OS
# stack); the ablation drops it to measure how much detection leans on it.
TCP_WINDOW = "Init Fwd Win Bytes"
FLOW_FEATURES = [c for c in COLUMNS if c != "Label"]

# Known problems with the original CSE-CIC-IDS2018 CICFlowMeter labels
# (Engelen et al. 2021; Liu et al., IEEE CNS 2022; DistriNet relabelling).
# `exclude` keeps a day-file out of baseline training and of the benchmark.
DATASET_NOTES = {
    "Infil": {
        "exclude": True,
        "caution": "Infiltration labels are largely unrecoverable (DistriNet): most 'Infilteration' "
        "flows are ordinary traffic from the victim host. Report separately, not in headline metrics.",
    },
    "Web": {
        "exclude": False,
        "caution": "Web attacks are under 0.1% of flows, so a window almost never reaches the attack "
        "threshold; about 42% of 23-02 Web Brute Force labels are wrong.",
    },
    "Bruteforce": {
        "exclude": False,
        "caution": "FTP-Patator hit a closed port (only RST replies); this file keeps 53 such flows. "
        "SSH-Bruteforce is the usable attack.",
    },
    "DoS2": {
        "exclude": False,
        "caution": "DoS-SlowHTTPTest never succeeded (55 flows here); DoS-Hulk is the usable attack.",
    },
    "DoS1": {"exclude": False, "caution": "About a quarter of GoldenEye flows are CICFlowMeter artefacts."},
    "DDoS2": {"exclude": False, "caution": "LOIC-UDP flows are mislabelled as HTTP in the original release."},
}


def _path(dataset_id: str) -> Path:
    path = (config.DATA_DIR / dataset_id).resolve()
    if path.parent != config.DATA_DIR.resolve() or path.suffix != ".parquet":
        raise ValueError(f"Unknown dataset: {dataset_id}")
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_id}")
    return path


def dataset_note(dataset_id: str) -> dict:
    for prefix, note in DATASET_NOTES.items():
        if dataset_id.startswith(prefix):
            return note
    return {"exclude": False, "caution": None}


@lru_cache(maxsize=64)
def _attack_share(path: str, mtime: float) -> float:
    labels = pd.read_parquet(path, columns=["Label"])["Label"].astype(str).str.strip()
    return round(float((labels != "Benign").mean()), 4)


def list_datasets() -> list[dict]:
    if not config.DATA_DIR.exists():
        return []
    out = []
    for p in sorted(config.DATA_DIR.glob("*.parquet")):
        note = dataset_note(p.name)
        out.append(
            {
                "dataset_id": p.name,
                "rows": pq.ParquetFile(p).metadata.num_rows,
                "attack_share": _attack_share(str(p), p.stat().st_mtime),
                "excluded_by_default": note["exclude"],
                "caution": note["caution"],
            }
        )
    return out


@lru_cache(maxsize=2)
def _frame(dataset_id: str) -> pd.DataFrame:
    df = pd.read_parquet(_path(dataset_id), columns=COLUMNS)
    df["Label"] = df["Label"].astype(str).str.strip()
    return df


def _share(mask: pd.Series) -> float:
    return round(float(mask.mean()), 3)


def summarize(window: pd.DataFrame, ablate_tcp_window: bool = False) -> dict:
    """Aggregate, label-free statistics for one window of flows."""
    columns = [c for c in SIGNATURE if not (ablate_tcp_window and c == TCP_WINDOW)]
    signature = window[columns].fillna(-1).astype("int64")
    packets = window["Total Fwd Packets"] + window["Total Backward Packets"]
    features = {
        "flows": int(len(window)),
        "tcp_share": _share(window["Protocol"] == 6),
        "udp_share": _share(window["Protocol"] == 17),
        "dominant_signature_share": round(
            float(signature.value_counts(normalize=True).iloc[0]), 3
        ),
        "unique_tcp_window_ratio": round(
            window["Init Fwd Win Bytes"].nunique() / len(window), 3
        ),
        "no_response_share": _share(window["Total Backward Packets"] == 0),
        "syn_share": _share(window["SYN Flag Count"] > 0),
        "rst_share": _share(window["RST Flag Count"] > 0),
        "fin_share": _share(window["FIN Flag Count"] > 0),
        "psh_share": _share(window["PSH Flag Count"] > 0),
        "mean_packets_per_flow": round(float(packets.mean()), 2),
        "mean_packets_per_sec": round(float(window["Flow Packets/s"].clip(lower=0).mean()), 2),
        "mean_bytes_per_sec": round(float(window["Flow Bytes/s"].clip(lower=0).mean()), 2),
        "mean_flow_duration_ms": round(float(window["Flow Duration"].mean()) / 1000, 2),
        "mean_packet_size": round(float(window["Avg Packet Size"].mean()), 2),
    }
    if ablate_tcp_window:
        del features["unique_tcp_window_ratio"]
    return features


def ground_truth(window: pd.DataFrame, threshold: float = 0.5) -> dict:
    """A window is an attack when at least `threshold` of its flows are attack flows."""
    counts = window["Label"].value_counts()
    attack_flows = int(counts.drop("Benign", errors="ignore").sum())
    return {
        "label_counts": {k: int(v) for k, v in counts.items()},
        "dominant_label": str(counts.index[0]),
        "attack_share": round(attack_flows / len(window), 3),
        "is_attack": attack_flows >= threshold * len(window),
        "threshold": threshold,
    }


def load_windows(
    dataset_id: str,
    windows: int = 10,
    window_size: int = 100,
    sampling: str = "spread",
    start_row: int = 0,
    *,
    seed: int | None = None,
    label_threshold: float = 0.5,
    ablate_tcp_window: bool = False,
    include_flows: bool = False,
) -> list[dict]:
    """Cut `windows` windows of `window_size` contiguous flows.

    sampling="spread" spaces them evenly across the whole capture (a mix of
    quiet and attack periods); "sequential" takes consecutive windows from
    `start_row`. A `seed` jitters each spread window inside its slot so repeated
    runs see different windows. The files carry no timestamps, so windows follow
    the CSV row order of the original release.

    `include_flows` adds the raw flow rows (for the ML baseline); callers must
    never pass them to the agents or store them.
    """
    df = _frame(dataset_id)
    n = len(df)
    if window_size < 10 or windows < 1:
        raise ValueError("Need at least 1 window of 10 flows.")
    if sampling == "spread":
        starts = np.linspace(0, max(0, n - window_size), windows).astype(int)
        if seed is not None:
            slot = max(1, (n - window_size) // max(1, windows))
            jitter = np.random.default_rng(seed).integers(0, slot, windows)
            starts = np.minimum(starts + jitter, max(0, n - window_size))
    elif sampling == "sequential":
        starts = [start_row + i * window_size for i in range(windows)]
        if starts[-1] + window_size > n:
            raise ValueError(f"Rows {start_row}–{starts[-1] + window_size} exceed dataset size {n}.")
    else:
        raise ValueError(f"Unknown sampling: {sampling}")

    out = []
    for i, start in enumerate(starts, start=1):
        chunk = df.iloc[int(start) : int(start) + window_size]
        window = {
            "index": i,
            "row_start": int(start),
            "row_end": int(start) + len(chunk),
            "features": summarize(chunk, ablate_tcp_window),
            "truth": ground_truth(chunk, label_threshold),
        }
        if include_flows:
            window["flows"] = chunk[FLOW_FEATURES]
        out.append(window)
    return out
