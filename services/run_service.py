"""Service boundary for executing the existing evaluation pilot."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from evaluation.evaluator import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_END_ROW,
    DEFAULT_START_ROW,
    MAX_GRAPH_EXECUTIONS,
    run_pilot,
)
from services.data_loader import SUPPORTED_EXTENSIONS


DEFAULT_DATASET_DIRECTORY = Path("data/raw")
SUPPORTED_DATASET_EXTENSIONS = SUPPORTED_EXTENSIONS


@dataclass(frozen=True)
class RunRequest:
    """Validated configuration accepted by the run service."""

    dataset_identifier: str
    start_row: int = DEFAULT_START_ROW
    end_row: int = DEFAULT_END_ROW
    batch_size: int = DEFAULT_BATCH_SIZE
    max_graph_executions: int = MAX_GRAPH_EXECUTIONS

    def __post_init__(self):
        if not isinstance(self.dataset_identifier, str):
            raise TypeError("dataset_identifier must be a string.")

        if not self.dataset_identifier.strip():
            raise ValueError("dataset_identifier must not be empty.")

        if Path(self.dataset_identifier).name != self.dataset_identifier:
            raise ValueError(
                "dataset_identifier must be a dataset filename, not a path."
            )

        if self.start_row < 0:
            raise ValueError("start_row must not be negative.")

        if self.end_row <= self.start_row:
            raise ValueError(
                "end_row must be greater than start_row."
            )

        if self.batch_size <= 0:
            raise ValueError("batch_size must be positive.")

        if self.max_graph_executions != MAX_GRAPH_EXECUTIONS:
            raise ValueError(
                "The pilot allows exactly one graph execution."
            )


@dataclass(frozen=True)
class RunResult:
    """The evaluator report exposed through the service boundary."""

    dataset: str
    pilot_start_row: int
    pilot_end_row: int
    pilot_batch_size: int
    pilot_selection: str
    run_status: str
    interruption_reason: Optional[str]
    run_final_decision_code: Optional[str]
    monitoring_window_count: int
    completed_window_count: int
    partial_window_count: int
    incomplete_window_count: int
    rows: List[Dict[str, Any]]
    monitoring_metrics: Dict[str, Any]
    llm_metrics: Dict[str, Any]
    pipeline_metrics: Dict[str, Any]
    graph_executions: int

    @classmethod
    def from_evaluator_report(
        cls,
        report: Dict[str, Any],
    ) -> "RunResult":
        required_fields = (
            "dataset",
            "pilot_start_row",
            "pilot_end_row",
            "pilot_batch_size",
            "pilot_selection",
            "run_status",
            "interruption_reason",
            "run_final_decision_code",
            "monitoring_window_count",
            "completed_window_count",
            "partial_window_count",
            "incomplete_window_count",
            "rows",
            "monitoring_metrics",
            "llm_metrics",
            "pipeline_metrics",
            "graph_executions",
        )
        missing_fields = [
            field
            for field in required_fields
            if field not in report
        ]
        if missing_fields:
            raise ValueError(
                "Evaluator report is missing fields: "
                + ", ".join(missing_fields)
            )

        return cls(
            dataset=report["dataset"],
            pilot_start_row=report["pilot_start_row"],
            pilot_end_row=report["pilot_end_row"],
            pilot_batch_size=report["pilot_batch_size"],
            pilot_selection=report["pilot_selection"],
            run_status=report["run_status"],
            interruption_reason=report["interruption_reason"],
            run_final_decision_code=report[
                "run_final_decision_code"
            ],
            monitoring_window_count=report[
                "monitoring_window_count"
            ],
            completed_window_count=report[
                "completed_window_count"
            ],
            partial_window_count=report["partial_window_count"],
            incomplete_window_count=report[
                "incomplete_window_count"
            ],
            rows=report["rows"],
            monitoring_metrics=report["monitoring_metrics"],
            llm_metrics=report["llm_metrics"],
            pipeline_metrics=report["pipeline_metrics"],
            graph_executions=report["graph_executions"],
        )

    def to_dict(self) -> Dict[str, Any]:
        """Return the evaluator-compatible report shape."""
        return {
            "dataset": self.dataset,
            "pilot_start_row": self.pilot_start_row,
            "pilot_end_row": self.pilot_end_row,
            "pilot_batch_size": self.pilot_batch_size,
            "pilot_selection": self.pilot_selection,
            "run_status": self.run_status,
            "interruption_reason": self.interruption_reason,
            "run_final_decision_code": (
                self.run_final_decision_code
            ),
            "monitoring_window_count": (
                self.monitoring_window_count
            ),
            "completed_window_count": (
                self.completed_window_count
            ),
            "partial_window_count": self.partial_window_count,
            "incomplete_window_count": (
                self.incomplete_window_count
            ),
            "rows": self.rows,
            "monitoring_metrics": self.monitoring_metrics,
            "llm_metrics": self.llm_metrics,
            "pipeline_metrics": self.pipeline_metrics,
            "graph_executions": self.graph_executions,
        }


class RunService:
    """Validate run requests and delegate execution to the evaluator."""

    def __init__(
        self,
        dataset_directory: Path = DEFAULT_DATASET_DIRECTORY,
        evaluator_runner: Callable = run_pilot,
    ):
        self.dataset_directory = Path(dataset_directory)
        self.evaluator_runner = evaluator_runner

    def resolve_dataset(self, dataset_identifier: str) -> Path:
        """Resolve an allowlisted dataset filename under the dataset directory."""
        if Path(dataset_identifier).name != dataset_identifier:
            raise ValueError(
                "dataset_identifier must be a dataset filename, not a path."
            )

        dataset_path = (
            self.dataset_directory / dataset_identifier
        ).resolve()
        dataset_directory = self.dataset_directory.resolve()

        if dataset_path.parent != dataset_directory:
            raise ValueError(
                "dataset_identifier must remain under the dataset directory."
            )

        if dataset_path.suffix.lower() not in (
            SUPPORTED_DATASET_EXTENSIONS
        ):
            raise ValueError(
                "Unsupported dataset file type."
            )

        if not dataset_path.is_file():
            raise FileNotFoundError(
                f"Dataset not found: {dataset_identifier}"
            )

        return dataset_path

    def run(
        self,
        request: RunRequest,
        graph_runner: Optional[Callable] = None,
    ) -> RunResult:
        """Execute the existing evaluator once for a validated request."""
        dataset_path = self.resolve_dataset(
            request.dataset_identifier
        )
        report = self.evaluator_runner(
            dataset_path=str(dataset_path),
            start_row=request.start_row,
            end_row=request.end_row,
            batch_size=request.batch_size,
            graph_runner=graph_runner,
            max_graph_executions=request.max_graph_executions,
        )
        return RunResult.from_evaluator_report(report)
