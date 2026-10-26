"""Tamper-evident audit trail: every record is hash-chained to the one before.

Changing, removing or reordering any record breaks `verify`.
"""

import hashlib
import json
from datetime import datetime, timezone

GENESIS = "0" * 64


def _digest(prev_hash: str, body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def append(chain: list[dict], actor: str, action: str, detail: dict) -> dict:
    prev_hash = chain[-1]["hash"] if chain else GENESIS
    body = {
        "seq": len(chain) + 1,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "actor": actor,
        "action": action,
        "detail": detail,
        "prev_hash": prev_hash,
    }
    record = {**body, "hash": _digest(prev_hash, body)}
    chain.append(record)
    return record


def verify(chain: list[dict]) -> dict:
    prev_hash = GENESIS
    for i, record in enumerate(chain, start=1):
        body = {k: v for k, v in record.items() if k != "hash"}
        if record.get("seq") != i or record.get("prev_hash") != prev_hash:
            return {"valid": False, "records": len(chain), "broken_at": i}
        if _digest(prev_hash, body) != record.get("hash"):
            return {"valid": False, "records": len(chain), "broken_at": i}
        prev_hash = record["hash"]
    return {"valid": True, "records": len(chain), "broken_at": None}
