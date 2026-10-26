"""Small JSON-backed persistence boundary for API run records."""

import json
import os
from pathlib import Path
from typing import Any, Dict


class RunStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> Dict[str, Dict[str, Any]]:
        if not self.path.exists():
            return {}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Unable to read persisted run records from {self.path}."
            ) from exc
        if not isinstance(payload, dict):
            raise RuntimeError(
                f"Persisted run records must be an object: {self.path}."
            )
        records: Dict[str, Dict[str, Any]] = {}
        for run_id, record in payload.items():
            if isinstance(run_id, str) and isinstance(record, dict):
                records[run_id] = record
        return records

    def save(self, records: Dict[str, Dict[str, Any]]) -> None:
        temporary_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
        try:
            temporary_path.write_text(
                json.dumps(records, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            os.replace(temporary_path, self.path)
        except OSError as exc:
            raise RuntimeError(
                f"Unable to persist run records to {self.path}."
            ) from exc
