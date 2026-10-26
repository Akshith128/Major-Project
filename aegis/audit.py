"""Tamper-evident audit trail.

Every record is SHA-256 hash-chained to the one before and authenticated with
an HMAC-SHA256 key that never lives in the run files (AEGIS_AUDIT_KEY, or a key
generated once in ~/.aegis). After each write the head of the chain — run id,
sequence number and hash — is HMAC-signed into a separate checkpoint log.

`verify` therefore detects:
  * a record that was edited, removed or reordered (hash or MAC mismatch);
  * a whole chain recomputed after an edit (the MACs need the key);
  * a chain cut short at the end (it is shorter than its latest checkpoint).

Limit: whoever holds the key can still forge records. A production system
would use asymmetric signatures and anchor checkpoints with a third party.
"""

import hashlib
import hmac
import json
from datetime import datetime, timezone

from . import config, keys

GENESIS = "0" * 64


def _digest(prev_hash: str, body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def _mac(message: str) -> str:
    return hmac.new(keys.audit_key(), message.encode(), hashlib.sha256).hexdigest()


def _checkpoint_mac(run_id: str, seq: int, head: str) -> str:
    return _mac(f"checkpoint:{run_id}:{seq}:{head}")


def append(chain: list[dict], actor: str, action: str, detail: dict, run_id: str | None = None) -> dict:
    prev_hash = chain[-1]["hash"] if chain else GENESIS
    body = {
        "seq": len(chain) + 1,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "actor": actor,
        "action": action,
        "detail": detail,
        "prev_hash": prev_hash,
    }
    digest = _digest(prev_hash, body)
    record = {**body, "hash": digest, "mac": _mac(digest)}
    chain.append(record)
    if run_id:
        _write_checkpoint(run_id, record)
    return record


def _write_checkpoint(run_id: str, record: dict) -> None:
    path = config.CHECKPOINT_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "run_id": run_id,
        "seq": record["seq"],
        "hash": record["hash"],
        "at": record["at"],
        "mac": _checkpoint_mac(run_id, record["seq"], record["hash"]),
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def latest_checkpoint(run_id: str) -> dict | None:
    path = config.CHECKPOINT_FILE
    if not path.exists():
        return None
    latest = None
    with path.open(encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("run_id") == run_id and (latest is None or entry["seq"] >= latest["seq"]):
                latest = entry
    return latest


def verify(chain: list[dict], run_id: str | None = None) -> dict:
    result = {"valid": True, "records": len(chain), "broken_at": None, "reason": None}
    unsigned = 0
    prev_hash = GENESIS
    for i, record in enumerate(chain, start=1):
        body = {k: v for k, v in record.items() if k not in ("hash", "mac")}
        if record.get("seq") != i or record.get("prev_hash") != prev_hash:
            return {**result, "valid": False, "broken_at": i, "reason": "Record missing or out of order."}
        if _digest(prev_hash, body) != record.get("hash"):
            return {**result, "valid": False, "broken_at": i, "reason": "Record content was changed."}
        if "mac" not in record:
            unsigned += 1  # written before records were signed
        elif not hmac.compare_digest(record["mac"], _mac(record["hash"])):
            return {**result, "valid": False, "broken_at": i, "reason": "Signature does not match: the chain was recomputed."}
        prev_hash = record["hash"]

    result["signed"] = unsigned == 0
    result["unsigned_records"] = unsigned
    checkpoint = latest_checkpoint(run_id) if run_id else None
    result["checkpoint_seq"] = checkpoint["seq"] if checkpoint else None
    if checkpoint:
        if not hmac.compare_digest(checkpoint["mac"], _checkpoint_mac(run_id, checkpoint["seq"], checkpoint["hash"])):
            return {**result, "valid": False, "reason": "Checkpoint signature does not match."}
        if len(chain) < checkpoint["seq"]:
            return {
                **result,
                "valid": False,
                "broken_at": len(chain) + 1,
                "reason": f"Trail was truncated: checkpoint records {checkpoint['seq']} entries, file has {len(chain)}.",
            }
        if chain[checkpoint["seq"] - 1]["hash"] != checkpoint["hash"]:
            return {**result, "valid": False, "broken_at": checkpoint["seq"], "reason": "Trail differs from its signed checkpoint."}
    return result
