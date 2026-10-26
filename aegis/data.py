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


def _path(dataset_id: str) -> Path:
    path = (config.DATA_DIR / dataset_id).resolve()
    if path.parent != config.DATA_DIR.resolve() or path.suffix != ".parquet":
        raise ValueError(f"Unknown dataset: {dataset_id}")
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_id}")
    return path


def list_datasets() -> list[dict]:
    if not config.DATA_DIR.exists():
        return []
    return [
        {"dataset_id": p.name, "rows": pq.ParquetFile(p).metadata.num_rows}
        for p in sorted(config.DATA_DIR.glob("*.parquet"))
    ]


@lru_cache(maxsize=2)
def _frame(dataset_id: str) -> pd.DataFrame:
    df = pd.read_parquet(_path(dataset_id), columns=COLUMNS)
    df["Label"] = df["Label"].astype(str).str.strip()
    return df


def _share(mask: pd.Series) -> float:
    return round(float(mask.mean()), 3)


def summarize(window: pd.DataFrame) -> dict:
    """Aggregate, label-free statistics for one window of flows."""
    signature = window[SIGNATURE].fillna(-1).astype("int64")
    packets = window["Total Fwd Packets"] + window["Total Backward Packets"]
    return {
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


def ground_truth(window: pd.DataFrame) -> dict:
    counts = window["Label"].value_counts()
    attack_flows = int(counts.drop("Benign", errors="ignore").sum())
    return {
        "label_counts": {k: int(v) for k, v in counts.items()},
        "dominant_label": str(counts.index[0]),
        "attack_share": round(attack_flows / len(window), 3),
        "is_attack": attack_flows * 2 >= len(window),
    }


def load_windows(
    dataset_id: str,
    windows: int = 10,
    window_size: int = 100,
    sampling: str = "spread",
    start_row: int = 0,
) -> list[dict]:
    """Cut `windows` windows of `window_size` contiguous flows.

    sampling="spread" spaces them evenly across the whole capture (a mix of
    quiet and attack periods); "sequential" takes consecutive windows from
    `start_row`.
    """
    df = _frame(dataset_id)
    n = len(df)
    if window_size < 10 or windows < 1:
        raise ValueError("Need at least 1 window of 10 flows.")
    if sampling == "spread":
        starts = np.linspace(0, max(0, n - window_size), windows).astype(int)
    elif sampling == "sequential":
        starts = [start_row + i * window_size for i in range(windows)]
        if starts[-1] + window_size > n:
            raise ValueError(f"Rows {start_row}–{starts[-1] + window_size} exceed dataset size {n}.")
    else:
        raise ValueError(f"Unknown sampling: {sampling}")

    out = []
    for i, start in enumerate(starts, start=1):
        chunk = df.iloc[int(start) : int(start) + window_size]
        out.append(
            {
                "index": i,
                "row_start": int(start),
                "row_end": int(start) + len(chunk),
                "features": summarize(chunk),
                "truth": ground_truth(chunk),
            }
        )
    return out
