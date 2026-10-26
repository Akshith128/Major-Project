"""Small, label-isolated evaluation harness for the existing graph."""

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.graph import build_graph
from services.data_loader import (
    create_monitoring_observations,
    load_network_data,
)


DEFAULT_DATASET = (
    "Web2-Friday-23-02-2018_TrafficForML_CICFlowMeter.parquet"
)
DEFAULT_START_ROW = 0
DEFAULT_END_ROW = 800
DEFAULT_BATCH_SIZE = 100
MAX_GRAPH_EXECUTIONS = 1
QUOTA_INTERRUPTION_PREFIX = "Gemini quota exceeded."


def binary_class(ground_truth: str) -> str:
    """Map the loader's dominant window label to ATTACK or BENIGN.

    ``create_monitoring_observations`` assigns the dominant label in each
    window. Any dominant label other than Benign is ATTACK, including mixed
    windows whose attack label has the largest count.
    """
    if str(ground_truth).strip().lower() == "benign":
        return "BENIGN"
    return "ATTACK"


def select_pilot_windows(
    dataframe,
    start_row: int = DEFAULT_START_ROW,
    end_row: int = DEFAULT_END_ROW,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> List[Dict[str, Any]]:
    """Create a fixed sequential pilot without inspecting labels."""
    if start_row < 0 or end_row <= start_row:
        raise ValueError("Pilot row range must be positive and ordered.")
    if end_row > len(dataframe):
        raise ValueError("Pilot row range exceeds dataset length.")

    selected = dataframe.iloc[start_row:end_row].copy()
    return create_monitoring_observations(
        selected,
        batch_size=batch_size,
    )


def agent_observation(window: Dict[str, Any]) -> Dict[str, Any]:
    """Return only the aggregate observation sent to the graph."""
    return dict(window["observation"])


def _prediction_from_detection(raw_response: Optional[str]):
    if not raw_response:
        return None
    if "THREAT_DETECTED: YES" in raw_response.upper():
        return "ATTACK"
    if "THREAT_DETECTED: NO" in raw_response.upper():
        return "BENIGN"
    return None


def overall_prediction(
    anomaly_detected: bool,
    llm_prediction: Optional[str],
) -> str:
    """Use LLM detection when invoked; otherwise use monitoring evidence."""
    if llm_prediction is not None:
        return llm_prediction
    return "ATTACK" if anomaly_detected else "BENIGN"


def _history_by_cycle(history: List[Dict[str, Any]], key: str):
    return {
        item.get(key): item
        for item in history
        if item.get(key) is not None
    }


def build_evaluation_rows(
    dataset_identifier: str,
    windows: List[Dict[str, Any]],
    graph_result: Optional[Dict[str, Any]] = None,
    run_status: str = "COMPLETED",
) -> List[Dict[str, Any]]:
    """Combine evaluator-side labels with optional graph outputs.

    The graph's final decision is an overall-run result and is returned by
    ``run_pilot`` rather than attached to individual monitoring rows.
    """
    graph_result = graph_result or {}
    monitoring_history = _history_by_cycle(
        [
            item
            for item in graph_result.get("severity_history", [])
            if item.get("stage") == "monitoring"
        ],
        "cycle",
    )
    detection_history = _history_by_cycle(
        graph_result.get("detection_history", []),
        "monitoring_cycle",
    )
    verification_history = _history_by_cycle(
        [
            item
            for item in graph_result.get("severity_history", [])
            if item.get("stage") == "verification"
        ],
        "monitoring_cycle",
    )
    final_decision_code = graph_result.get("final_decision_code")
    has_final_decision = (
        isinstance(final_decision_code, str)
        and bool(final_decision_code.strip())
    )

    rows = []
    for index, window in enumerate(windows, start=1):
        monitoring = monitoring_history.get(index, {})
        detection = detection_history.get(index)
        verification = verification_history.get(index, {})
        has_monitoring = bool(monitoring)
        if not has_monitoring:
            window_status = "INCOMPLETE"
        elif run_status == "INTERRUPTED":
            window_status = "PARTIAL"
        elif run_status == "COMPLETED" and has_final_decision:
            window_status = "COMPLETED"
        else:
            window_status = "INCOMPLETE"
        raw_detection = (
            detection.get("raw_response")
            if detection
            else None
        )
        llm_prediction = _prediction_from_detection(raw_detection)
        anomaly_detected = monitoring.get("anomaly_detected")
        monitoring_prediction = (
            "ATTACK"
            if anomaly_detected is True
            else "BENIGN"
            if anomaly_detected is False
            else None
        )
        pipeline_prediction = (
            overall_prediction(
                anomaly_detected,
                llm_prediction,
            )
            if window_status == "COMPLETED"
            else None
        )

        rows.append(
            {
                "dataset": dataset_identifier,
                "window": index,
                "window_status": window_status,
                "ground_truth_dominant_label": window["ground_truth"],
                "ground_truth_binary_class": binary_class(
                    window["ground_truth"]
                ),
                "label_counts": dict(window["label_counts"]),
                "monitoring_anomaly_prediction": monitoring_prediction,
                "llm_detection_prediction": llm_prediction,
                "llm_detection_invoked": detection is not None,
                "overall_pipeline_prediction": pipeline_prediction,
                "raw_detection_response": raw_detection,
                "enforced_severity": monitoring.get("severity"),
                "risk_score": monitoring.get("risk_score"),
                "verification_outcome": verification.get(
                    "verification_status"
                ),
            }
        )
    return rows


def binary_metrics(rows: List[Dict[str, Any]], prediction_key: str):
    """Calculate metrics while exposing the evaluated-row denominator.

    Rows with ``None`` for ``prediction_key`` are counted in
    ``missing_predictions`` and excluded from TP/TN/FP/FN denominators.
    Therefore ``evaluated_rows`` is the denominator for accuracy and the
    confusion-matrix-derived metrics, while ``total_rows`` is the full
    supplied row count.
    """
    counts = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    for row in rows:
        actual = row["ground_truth_binary_class"]
        prediction = row.get(prediction_key)
        if prediction is None:
            continue
        if actual == "ATTACK" and prediction == "ATTACK":
            counts["TP"] += 1
        elif actual == "BENIGN" and prediction == "BENIGN":
            counts["TN"] += 1
        elif actual == "BENIGN" and prediction == "ATTACK":
            counts["FP"] += 1
        elif actual == "ATTACK" and prediction == "BENIGN":
            counts["FN"] += 1

    tp = counts["TP"]
    tn = counts["TN"]
    fp = counts["FP"]
    fn = counts["FN"]
    total = tp + tn + fp + fn

    def safe(numerator, denominator):
        return numerator / denominator if denominator else 0.0

    return {
        **counts,
        "accuracy": safe(tp + tn, total),
        "precision": safe(tp, tp + fp),
        "recall": safe(tp, tp + fn),
        "f1": safe(2 * tp, 2 * tp + fp + fn),
        "false_positive_rate": safe(fp, fp + tn),
        "evaluated_rows": total,
        "total_rows": len(rows),
        "missing_predictions": len(rows) - total,
    }


def detector_metrics(rows: List[Dict[str, Any]]):
    """Report detector-only metrics and invocation accounting."""
    invoked_rows = [
        row
        for row in rows
        if row["llm_detection_invoked"]
    ]
    valid_rows = [
        row
        for row in invoked_rows
        if row["llm_detection_prediction"] is not None
    ]
    metrics = binary_metrics(
        valid_rows,
        "llm_detection_prediction",
    )
    metrics.update(
        {
            "detector_invocations": len(invoked_rows),
            "invalid_or_unparseable_responses": (
                len(invoked_rows) - len(valid_rows)
            ),
            "fallback_predictions": sum(
                row.get("overall_pipeline_prediction") is not None
                and row["llm_detection_prediction"] is None
                for row in rows
            ),
        }
    )
    return metrics


def run_pilot(
    dataset_path: str = str(
        Path("data/raw") / DEFAULT_DATASET
    ),
    start_row: int = DEFAULT_START_ROW,
    end_row: int = DEFAULT_END_ROW,
    batch_size: int = DEFAULT_BATCH_SIZE,
    graph_runner: Optional[Callable] = None,
    max_graph_executions: int = MAX_GRAPH_EXECUTIONS,
):
    """Run at most one existing graph execution for an explicit pilot."""
    if max_graph_executions != 1:
        raise ValueError(
            "The pilot allows exactly one graph execution."
        )

    dataframe = load_network_data(dataset_path)
    windows = select_pilot_windows(
        dataframe,
        start_row=start_row,
        end_row=end_row,
        batch_size=batch_size,
    )
    graph = graph_runner or build_graph()
    observations = [
        agent_observation(window)
        for window in windows
    ]
    initial_state = {
        "raw_data": observations[0],
        "monitoring_observations": observations,
        "monitoring_count": 0,
        "severity": "LOW",
        "risk_score": 0.0,
        "recovery_count": 0,
        "severity_history": [],
        "detection_history": [],
        "response_history": [],
        "response_pending": False,
        "response_required": False,
        "response_completed": False,
        "response_cycle": 0,
        "status": "started",
        "interrupted": False,
        "run_status": "RUNNING",
        "interruption_reason": None,
        "monitoring_mode": "OFFLINE_DATASET",
    }
    latest_state = None
    run_status = "COMPLETED"
    interruption_reason = None
    try:
        for state in graph.stream(
            initial_state,
            stream_mode="values",
        ):
            latest_state = state
    except RuntimeError as exc:
        if not str(exc).startswith(
            QUOTA_INTERRUPTION_PREFIX
        ):
            raise
        run_status = "INTERRUPTED"
        interruption_reason = str(exc)
        latest_state = (
            latest_state
            if latest_state is not None
            else initial_state
        )
        latest_state.update(
            {
                "interrupted": True,
                "run_status": run_status,
                "interruption_reason": (
                    interruption_reason
                ),
            }
        )

    result = latest_state or {}
    rows = build_evaluation_rows(
        Path(dataset_path).name,
        windows,
        result,
        run_status=run_status,
    )
    status_counts = {
        status: sum(
            row["window_status"] == status
            for row in rows
        )
        for status in (
            "COMPLETED",
            "PARTIAL",
            "INCOMPLETE",
        )
    }
    final_decision_code = result.get("final_decision_code")
    if (
        run_status == "COMPLETED"
        and not (
            isinstance(final_decision_code, str)
            and bool(final_decision_code.strip())
        )
    ):
        run_status = "INCOMPLETE"
    run_final_decision_code = (
        final_decision_code
        if (
            run_status == "COMPLETED"
            and isinstance(final_decision_code, str)
            and bool(final_decision_code.strip())
        )
        else None
    )
    return {
        "dataset": Path(dataset_path).name,
        "pilot_start_row": start_row,
        "pilot_end_row": end_row,
        "pilot_batch_size": batch_size,
        "pilot_selection": "FIXED_SEQUENTIAL_LABEL_INDEPENDENT",
        "run_status": run_status,
        "interruption_reason": interruption_reason,
        "run_final_decision_code": run_final_decision_code,
        "monitoring_window_count": len(windows),
        "completed_window_count": status_counts["COMPLETED"],
        "partial_window_count": status_counts["PARTIAL"],
        "incomplete_window_count": status_counts["INCOMPLETE"],
        "rows": rows,
        "monitoring_metrics": binary_metrics(
            rows,
            "monitoring_anomaly_prediction",
        ),
        "llm_metrics": detector_metrics(rows),
        "pipeline_metrics": binary_metrics(
            rows,
            "overall_pipeline_prediction",
        ),
        "graph_executions": 1,
    }
