"""Opt-in capture boundary for genuine detector-output recordings.

This utility is intentionally not wired into production execution. A caller
at the existing detector boundary may inject it only after a real detector
invocation has returned. Disabled capture is a no-op.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class DetectorOutputRecorder:
    """Capture genuine detector results without changing the detector result."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        source: Optional[str] = None,
    ):
        self.enabled = enabled
        self.source = source.strip() if isinstance(source, str) else source
        self.records: List[Dict[str, Any]] = []
        if self.enabled and not self.source:
            raise ValueError(
                "An explicit source is required when capture is enabled."
            )

    def record_invocation(
        self,
        *,
        dataset: str,
        window: int,
        row_start: int,
        row_end: int,
        raw_output: Optional[str],
        parsed_prediction: Optional[str],
        invocation_status: str = "INVOKED",
        timestamp: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Record an already completed genuine invocation, if enabled."""
        if invocation_status != "INVOKED":
            raise ValueError(
                "record_invocation only accepts an actual invocation."
            )
        if parsed_prediction not in {None, "BENIGN", "ATTACK"}:
            raise ValueError(
                "parsed_prediction must be BENIGN, ATTACK, or null."
            )
        if raw_output is not None and not isinstance(raw_output, str):
            raise ValueError("raw_output must be a string or null.")
        if not self.enabled:
            return None
        captured_at = timestamp or datetime.now(
            timezone.utc
        ).isoformat()
        record = {
            "dataset": dataset,
            "window": window,
            "row_start": row_start,
            "row_end": row_end,
            "detector_invoked": True,
            "raw_output": raw_output,
            "parsed_prediction": parsed_prediction,
            "source": self.source,
            "provenance": "genuine_recorded",
            "captured_at": captured_at,
        }
        self.records.append(record)
        return dict(record)

    def record_non_invocation(self, **_: Any) -> None:
        """Do not manufacture a detector record when no invocation occurred."""
        return None

    def export_records(self) -> List[Dict[str, Any]]:
        """Return a copy suitable for explicit offline replay."""
        return [dict(record) for record in self.records]
