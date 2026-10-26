"""System-wide stop control (EU AI Act Art. 14(4)(e): halt the system in a safe state).

While paused, no run can start and a running run stops after its current
window. Nothing is ever executed automatically, so stopping leaves the network
untouched; recommendations already made stay pending for review.
"""

import json
from datetime import datetime, timezone

from . import config


def state() -> dict:
    if not config.CONTROL_FILE.exists():
        return {"paused": False, "by": None, "at": None, "reason": None}
    return json.loads(config.CONTROL_FILE.read_text(encoding="utf-8"))


def set_paused(paused: bool, by: str, reason: str = "") -> dict:
    current = {
        "paused": paused,
        "by": by,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "reason": reason.strip() or None,
    }
    config.CONTROL_FILE.parent.mkdir(parents=True, exist_ok=True)
    config.CONTROL_FILE.write_text(json.dumps(current), encoding="utf-8")
    return current


def is_paused() -> bool:
    return bool(state()["paused"])
