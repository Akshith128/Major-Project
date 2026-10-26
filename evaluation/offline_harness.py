"""Deterministic, offline evaluation utilities.

This module never builds or invokes the LangGraph execution.  It accepts
evaluation-only window records and deterministic state examples so that
accounting, routing, completion, and serialization can be tested separately
from model-dependent behavior.
"""

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from core.graph import (
    monitoring_completed,
    route_after_monitoring,
    route_after_risk,
    route_after_verification,
)
from evaluation.evaluator import binary_class, binary_metrics
from services.data_loader import (
    create_monitoring_observations,
    find_column,
    get_ground_truth,
    load_network_data,
)


LABEL_MAPPING_RULE = (
    "Benign (case-insensitive after trimming) maps to BENIGN; "
    "every other dominant label maps to ATTACK."
)

DEFAULT_REPLAY_MOCK_CONFIGURATION = "deterministic-feature-v1"
RECORDED_PROVENANCES = {
    "genuine_recorded",
    "synthetic_test",
}
RECORDED_PREDICTIONS_VERSION = "recorded-detector-v1"


def _safe_metric(rows: List[Dict[str, Any]], prediction_key: str):
    metrics = binary_metrics(rows, prediction_key)
    evaluated = metrics["evaluated_rows"]
    metrics.update(
        {
            "population_rows": len(rows),
            "total_window_population": len(rows),
            "eligible_predictions": evaluated,
            "excluded_rows": len(rows) - evaluated,
        }
    )
    return metrics


def _detector_metric(rows: List[Dict[str, Any]]):
    invoked = [row for row in rows if row.get("llm_detection_invoked")]
    valid = [
        row for row in invoked
        if row.get("llm_detection_prediction") is not None
    ]
    metrics = _safe_metric(valid, "llm_detection_prediction")
    metrics.update(
        {
            "population_rows": len(rows),
            "total_window_population": len(rows),
            "invoked_rows": len(invoked),
            "invalid_or_unparseable_responses": (
                len(invoked) - len(valid)
            ),
            "missing_predictions": len(rows) - len(valid),
            "excluded_rows": len(rows) - len(valid),
            "not_invoked_rows": sum(
                not row.get("llm_detection_invoked")
                for row in rows
            ),
            "unparseable_rows": sum(
                row.get("llm_detection_invoked")
                and row.get("detector_prediction_status")
                == "UNPARSEABLE"
                for row in rows
            ),
            "invoked_missing_rows": sum(
                row.get("llm_detection_invoked")
                and row.get("detector_prediction_status") == "MISSING"
                for row in rows
            ),
        }
    )
    return metrics


def _normalise_window(index: int, record: Dict[str, Any]) -> Dict[str, Any]:
    """Copy evaluation fields without adding labels to agent-facing state."""
    row = {
        "window": record.get("window", index),
        "row_start": record.get("row_start"),
        "row_end": record.get("row_end"),
        "label_counts": dict(record.get("label_counts", {})),
        "ground_truth_dominant_label": record.get(
            "ground_truth_dominant_label",
            record.get("ground_truth"),
        ),
        "ground_truth_binary_class": record.get(
            "ground_truth_binary_class"
        ),
        "aggregated_observation": record.get(
            "aggregated_observation",
            record.get("observation"),
        ),
        "window_flow_count": record.get("window_flow_count"),
        "partial_final_window": bool(
            record.get("partial_final_window", False)
        ),
        "monitoring_anomaly_prediction": record.get(
            "monitoring_anomaly_prediction"
        ),
        "llm_detection_prediction": record.get(
            "llm_detection_prediction"
        ),
        "llm_detection_invoked": bool(
            record.get("llm_detection_invoked", False)
        ),
        "overall_pipeline_prediction": record.get(
            "overall_pipeline_prediction"
        ),
        "window_status": record.get("window_status", "COMPLETED"),
        "fallback_source": record.get("fallback_source"),
        "detector_invocation_reason": record.get(
            "detector_invocation_reason"
        ),
        "raw_detection_response": record.get(
            "raw_detection_response"
        ),
        "detector_output_source": record.get(
            "detector_output_source"
        ),
        "detector_output_provenance": record.get(
            "detector_output_provenance"
        ),
        "detector_output_captured_at": record.get(
            "detector_output_captured_at"
        ),
        "mock_agent_configuration": record.get(
            "mock_agent_configuration"
        ),
    }
    if row["ground_truth_binary_class"] is None:
        row["ground_truth_binary_class"] = binary_class(
            row["ground_truth_dominant_label"]
        )
    if not row["llm_detection_invoked"]:
        row["detector_prediction_status"] = "NOT_INVOKED"
    elif row["llm_detection_prediction"] is not None:
        row["detector_prediction_status"] = "PARSED"
    elif row["raw_detection_response"] is not None:
        row["detector_prediction_status"] = "UNPARSEABLE"
    else:
        row["detector_prediction_status"] = "MISSING"
    if (
        row["overall_pipeline_prediction"] is not None
        and row["llm_detection_prediction"] is None
        and row["fallback_source"] is None
    ):
        row["fallback_source"] = "monitoring"
    return row


def evaluate_windows(
    windows: Iterable[Dict[str, Any]],
    *,
    dataset: Optional[str] = None,
    run_status: str = "COMPLETED",
    run_final_decision_code: Optional[str] = None,
    interruption_reason: Optional[str] = None,
    selection_rule: str = "SYNTHETIC_FIXED_LABEL_INDEPENDENT",
) -> Dict[str, Any]:
    """Evaluate supplied deterministic records without running any agents."""
    rows = [
        _normalise_window(index, record)
        for index, record in enumerate(windows, start=1)
    ]
    completed_status = [
        row for row in rows
        if row["window_status"] == "COMPLETED"
    ]
    completed = [
        row for row in rows
        if (
            row["window_status"] == "COMPLETED"
            and not row["partial_final_window"]
        )
    ]
    fallback_count = sum(
        row["overall_pipeline_prediction"] is not None
        and row["llm_detection_prediction"] is None
        for row in rows
    )
    return {
        "evaluation_configuration": {
            "dataset": dataset,
            "selection_rule": selection_rule,
            "agent_execution": "NOT_INVOKED",
        },
        "label_mapping_rule": LABEL_MAPPING_RULE,
        "windows": rows,
        "prediction_availability": {
            "total_windows": len(rows),
            "monitoring_predictions": sum(
                row["monitoring_anomaly_prediction"] is not None
                for row in rows
            ),
            "detector_invocations": sum(
                row["llm_detection_invoked"] for row in rows
            ),
            "detector_predictions": sum(
                row["llm_detection_prediction"] is not None
                for row in rows
            ),
            "overall_predictions": sum(
                row["overall_pipeline_prediction"] is not None
                for row in rows
            ),
            "fallback_predictions": fallback_count,
        },
        "metrics": {
            "monitoring": _safe_metric(
                rows,
                "monitoring_anomaly_prediction",
            ),
            "detector": _detector_metric(rows),
            "overall_pipeline": _safe_metric(
                rows,
                "overall_pipeline_prediction",
            ),
            "completed_pipeline": _safe_metric(
                completed,
                "overall_pipeline_prediction",
            ),
        },
        "run": {
            "run_status": run_status,
            "run_final_decision_code": (
                run_final_decision_code
                if run_status == "COMPLETED"
                else None
            ),
            "interruption_reason": interruption_reason,
            "completed_window_count": len(completed_status),
            "partial_window_count": sum(
                row["window_status"] == "PARTIAL" for row in rows
            ),
            "incomplete_window_count": sum(
                row["window_status"] == "INCOMPLETE" for row in rows
            ),
        },
    }


def serialize_result(result: Dict[str, Any]) -> str:
    """Return deterministic JSON and fail explicitly for non-serializable data."""
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


def deterministic_mock_agents(
    observation: Dict[str, Any],
    window_index: int,
) -> Dict[str, Any]:
    """Return model-free outputs based only on aggregate observation features."""
    packet_rate = float(
        observation.get(
            "average_flow_packets_per_second",
            0,
        )
        or 0
    )
    rst_flags = int(observation.get("rst_flag_count", 0) or 0)
    anomaly_detected = packet_rate >= 1000 or rst_flags >= 50
    detector_invoked = anomaly_detected
    detector_prediction = None
    raw_response = None
    if detector_invoked:
        if window_index % 3 == 0:
            raw_response = "UNPARSEABLE_DETECTOR_OUTPUT"
        else:
            detector_prediction = (
                "ATTACK" if anomaly_detected else "BENIGN"
            )
            raw_response = "MOCK_THREAT_DETECTED: YES"

    overall_prediction = (
        detector_prediction
        if detector_prediction is not None
        else (
            "ATTACK"
            if anomaly_detected
            else "BENIGN"
        )
    )
    return {
        "monitoring_anomaly_prediction": (
            "ATTACK" if anomaly_detected else "BENIGN"
        ),
        "detector_invoked": detector_invoked,
        "detector_invocation_reason": (
            "deterministic_anomaly_policy"
            if detector_invoked
            else "monitoring_anomaly_not_detected"
        ),
        "detector_prediction": detector_prediction,
        "detector_raw_response": raw_response,
        "overall_pipeline_prediction": overall_prediction,
        "fallback_source": (
            "monitoring"
            if detector_prediction is None
            else None
        ),
        "mock_agent_configuration": DEFAULT_REPLAY_MOCK_CONFIGURATION,
    }


def _validate_recorded_output(
    record: Dict[str, Any],
    *,
    dataset_identifier: str,
    expected_window: Dict[str, Any],
    expected_provenance: str,
) -> Dict[str, Any]:
    """Validate one explicit detector record against one exact window."""
    if not isinstance(record, dict):
        raise ValueError("Each recorded detector output must be an object.")
    if record.get("dataset") != dataset_identifier:
        raise ValueError("Recorded output dataset does not match the replay.")
    if record.get("provenance") != expected_provenance:
        raise ValueError("Unsupported or unexpected recorded-output provenance.")
    if record.get("provenance") not in RECORDED_PROVENANCES:
        raise ValueError("Unsupported recorded-output provenance.")
    if not isinstance(record.get("source"), str) or not record["source"].strip():
        raise ValueError("Recorded output requires a non-empty source.")
    if record["provenance"] == "genuine_recorded" and not record.get(
        "captured_at"
    ):
        raise ValueError(
            "Genuine recorded output requires a capture timestamp."
        )
    if record.get("derived_from_ground_truth", False):
        raise ValueError("Ground-truth-derived detector outputs are prohibited.")
    forbidden = {
        "ground_truth",
        "ground_truth_binary_class",
        "ground_truth_dominant_label",
        "label_counts",
        "labels",
    }
    if forbidden.intersection(record):
        raise ValueError("Recorded detector outputs must not contain labels.")
    identity = (
        record.get("window"),
        record.get("row_start"),
        record.get("row_end"),
    )
    expected_identity = (
        expected_window["window"],
        expected_window["row_start"],
        expected_window["row_end"],
    )
    if identity != expected_identity:
        raise ValueError("Recorded output does not match the exact window.")
    if not isinstance(record.get("detector_invoked"), bool):
        raise ValueError("detector_invoked must be a boolean.")
    prediction = record.get("parsed_prediction")
    if prediction is not None and prediction not in {"BENIGN", "ATTACK"}:
        raise ValueError("parsed_prediction must be BENIGN, ATTACK, or null.")
    raw_output = record.get("raw_output")
    if raw_output is not None and not isinstance(raw_output, str):
        raise ValueError("raw_output must be a string or null.")
    if not record.get("detector_invoked") and (
        prediction is not None or raw_output is not None
    ):
        raise ValueError(
            "Non-invoked detector records cannot contain detector outputs."
        )
    return {
        "detector_invoked": record["detector_invoked"],
        "detector_prediction": prediction,
        "detector_raw_response": raw_output,
        "detector_invocation_reason": record.get(
            "invocation_reason",
            "recorded_output",
        ),
        "detector_output_source": record.get(
            "source",
            "recorded_local_fixture",
        ),
        "detector_output_provenance": record["provenance"],
        "detector_output_captured_at": record.get("captured_at"),
    }


def replay_recorded_detector_outputs(
    dataset_path: str,
    *,
    start_row: int,
    end_row: int,
    batch_size: int,
    recorded_outputs: Iterable[Dict[str, Any]],
    expected_provenance: str,
    monitoring_agent=deterministic_mock_agents,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluate explicit detector records against fixed production windows."""
    if expected_provenance not in RECORDED_PROVENANCES:
        raise ValueError("Unsupported expected recorded-output provenance.")
    dataframe = load_network_data(dataset_path)
    if start_row < 0 or end_row <= start_row or end_row > len(dataframe):
        raise ValueError("Recorded replay row range is invalid.")
    selected = dataframe.iloc[start_row:end_row].copy()
    windows = create_monitoring_observations(
        selected,
        batch_size=batch_size,
    )
    expected_windows = []
    for index, window in enumerate(windows, start=1):
        row_start = start_row + (index - 1) * batch_size
        expected_windows.append(
            {
                "window": index,
                "row_start": row_start,
                "row_end": row_start + window["dataset_flow_count"],
                "window_flow_count": window["dataset_flow_count"],
                "partial_final_window": (
                    window["dataset_flow_count"] < batch_size
                ),
                "ground_truth": window["ground_truth"],
                "label_counts": window["label_counts"],
                "observation": dict(window["observation"]),
            }
        )
    by_identity = {}
    for record in recorded_outputs:
        if not isinstance(record, dict):
            raise ValueError("Recorded detector output must be an object.")
        identity = (
            record.get("window"),
            record.get("row_start"),
            record.get("row_end"),
        )
        if identity in by_identity:
            raise ValueError("Duplicate recorded window identity.")
        by_identity[identity] = record
    if set(by_identity) - {
        (item["window"], item["row_start"], item["row_end"])
        for item in expected_windows
    }:
        raise ValueError("Recorded output contains an unknown window.")
    records = []
    for expected in expected_windows:
        identity = (
            expected["window"],
            expected["row_start"],
            expected["row_end"],
        )
        if identity not in by_identity:
            raise ValueError("Recorded detector output is missing a window.")
        recorded = _validate_recorded_output(
            by_identity[identity],
            dataset_identifier=Path(dataset_path).name,
            expected_window=expected,
            expected_provenance=expected_provenance,
        )
        monitoring = monitoring_agent(
            dict(expected["observation"]),
            expected["window"],
        )
        if "monitoring_anomaly_prediction" not in monitoring:
            raise ValueError("Monitoring output lacks a binary prediction.")
        detector_prediction = recorded["detector_prediction"]
        overall_prediction = (
            detector_prediction
            if detector_prediction is not None
            else monitoring["monitoring_anomaly_prediction"]
        )
        records.append(
            {
                **expected,
                "aggregated_observation": dict(expected["observation"]),
                "window_status": "COMPLETED",
                "monitoring_anomaly_prediction": monitoring[
                    "monitoring_anomaly_prediction"
                ],
                "llm_detection_invoked": recorded["detector_invoked"],
                "llm_detection_prediction": detector_prediction,
                "detector_prediction_status": (
                    "PARSED"
                    if detector_prediction is not None
                    else (
                        "UNPARSEABLE"
                        if recorded["detector_raw_response"] is not None
                        else (
                            "MISSING"
                            if recorded["detector_invoked"]
                            else "NOT_INVOKED"
                        )
                    )
                ),
                "overall_pipeline_prediction": overall_prediction,
                "fallback_source": (
                    "monitoring"
                    if detector_prediction is None
                    else None
                ),
                "raw_detection_response": recorded[
                    "detector_raw_response"
                ],
                "detector_invocation_reason": recorded[
                    "detector_invocation_reason"
                ],
                "detector_output_source": recorded[
                    "detector_output_source"
                ],
                "detector_output_provenance": recorded[
                    "detector_output_provenance"
                ],
                "detector_output_captured_at": recorded[
                    "detector_output_captured_at"
                ],
            }
        )
    result = evaluate_windows(
        records,
        dataset=Path(dataset_path).name,
        selection_rule="FIXED_CONTIGUOUS_LABEL_INDEPENDENT",
    )
    result["evaluation_configuration"].update(
        {
            "dataset_format": Path(dataset_path).suffix.lower().lstrip("."),
            "start_row": start_row,
            "end_row": end_row,
            "batch_size": batch_size,
            "recorded_predictions_version": RECORDED_PREDICTIONS_VERSION,
            "recorded_output_provenance": expected_provenance,
            "agent_execution": "NOT_INVOKED",
        }
    )
    if output_path is not None:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(serialize_result(result), encoding="utf-8")
        result["artifact_path"] = str(output)
    return result


def replay_dataset_slice(
    dataset_path: str,
    *,
    start_row: int,
    end_row: int,
    batch_size: int,
    mock_agent=deterministic_mock_agents,
    mock_configuration_id: str = DEFAULT_REPLAY_MOCK_CONFIGURATION,
    run_status: str = "COMPLETED",
    interruption_reason: Optional[str] = None,
    interrupt_after_window: Optional[int] = None,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Replay one fixed dataset slice without production graph execution.

    The injected mock receives only the aggregate observation and window
    index. Ground-truth fields are added to the evaluation record afterward.
    """
    if start_row < 0 or end_row <= start_row:
        raise ValueError("Replay row range must be positive and ordered.")
    if batch_size <= 0:
        raise ValueError("Replay batch size must be positive.")
    if run_status not in {"COMPLETED", "INTERRUPTED"}:
        raise ValueError("Replay run_status must be COMPLETED or INTERRUPTED.")

    dataframe = load_network_data(dataset_path)
    if end_row > len(dataframe):
        raise ValueError("Replay row range exceeds dataset length.")
    selected = dataframe.iloc[start_row:end_row].copy()
    label_column = find_column(selected, ["Label"])
    windows = create_monitoring_observations(
        selected,
        batch_size=batch_size,
    )
    records = []
    mock_invocations = 0
    for index, window in enumerate(windows, start=1):
        row_start = start_row + (index - 1) * batch_size
        row_end = min(row_start + window["dataset_flow_count"], end_row)
        is_interrupted = (
            run_status == "INTERRUPTED"
            and interrupt_after_window is not None
            and index > interrupt_after_window
        )
        # This is the only object passed into the injected mock.
        agent_input = dict(window["observation"])
        if is_interrupted:
            mock_output = {}
            status = "INCOMPLETE"
        else:
            mock_output = mock_agent(agent_input, index)
            mock_invocations += 1
            status = (
                "PARTIAL"
                if run_status == "INTERRUPTED"
                and interrupt_after_window == index
                else "COMPLETED"
            )
        records.append(
            {
                "window": index,
                "row_start": row_start,
                "row_end": row_end,
                "window_flow_count": window["dataset_flow_count"],
                "partial_final_window": (
                    window["dataset_flow_count"] < batch_size
                ),
                "label_counts": dict(window["label_counts"]),
                "ground_truth_dominant_label": window["ground_truth"],
                "aggregated_observation": agent_input,
                "window_status": status,
                "monitoring_anomaly_prediction": mock_output.get(
                    "monitoring_anomaly_prediction"
                ),
                "llm_detection_invoked": bool(
                    mock_output.get("detector_invoked", False)
                ),
                "detector_invocation_reason": mock_output.get(
                    "detector_invocation_reason"
                ),
                "llm_detection_prediction": mock_output.get(
                    "detector_prediction"
                ),
                "raw_detection_response": mock_output.get(
                    "detector_raw_response"
                ),
                "overall_pipeline_prediction": (
                    mock_output.get("overall_pipeline_prediction")
                    if status == "COMPLETED"
                    else None
                ),
                "fallback_source": mock_output.get("fallback_source"),
                "mock_agent_configuration": mock_output.get(
                    "mock_agent_configuration",
                    mock_configuration_id,
                ),
            }
        )

    full_truth = get_ground_truth(selected)
    result = evaluate_windows(
        records,
        dataset=Path(dataset_path).name,
        run_status=run_status,
        interruption_reason=interruption_reason,
        selection_rule="FIXED_CONTIGUOUS_LABEL_INDEPENDENT",
    )
    result["evaluation_configuration"].update(
        {
            "dataset_format": Path(dataset_path).suffix.lower().lstrip("."),
            "start_row": start_row,
            "end_row": end_row,
            "batch_size": batch_size,
            "label_column": str(label_column),
            "mock_configuration_id": mock_configuration_id,
            "graph_execution": "NOT_INVOKED",
            "full_selected_label_counts": full_truth["label_counts"],
        }
    )
    result["prediction_availability"]["mock_agent_invocations"] = (
        mock_invocations
    )
    if output_path is not None:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            serialize_result(result),
            encoding="utf-8",
        )
        result["artifact_path"] = str(output)
    return result


def inspect_dataset(
    dataset_path: str,
    *,
    start_row: Optional[int] = None,
    end_row: Optional[int] = None,
) -> Dict[str, Any]:
    """Inspect one dataset offline; no agents or graph execution are called."""
    dataframe = load_network_data(dataset_path)
    label_column = find_column(dataframe, ["Label"])
    full_truth = get_ground_truth(dataframe)
    selected = dataframe
    if start_row is not None or end_row is not None:
        selected = dataframe.iloc[
            start_row or 0:end_row
        ]
    selected_truth = get_ground_truth(selected)
    binary_distribution = {"BENIGN": 0, "ATTACK": 0}
    for label, count in full_truth["label_counts"].items():
        binary_distribution[
            binary_class(label)
        ] += count
    columns = [str(column) for column in dataframe.columns]
    lower_columns = {column.lower(): column for column in columns}
    timestamp_columns = [
        column for column in columns
        if "time" in column.lower() or "date" in column.lower()
    ]
    grouping_columns = [
        column for column in columns
        if any(token in column.lower() for token in (
            "ip", "port", "flow id", "protocol"
        ))
    ]
    flow_identifier_columns = [
        column for column in columns
        if "flow id" in column.lower()
    ]
    return {
        "filename": Path(dataset_path).name,
        "format": Path(dataset_path).suffix.lower().lstrip("."),
        "row_count": len(dataframe),
        "column_count": len(columns),
        "label_columns": [str(label_column)],
        "label_distribution": full_truth["label_counts"],
        "binary_label_distribution": binary_distribution,
        "missing_label_count": int(dataframe[label_column].isna().sum()),
        "exact_duplicate_row_count": int(
            dataframe.duplicated().sum()
        ),
        "likely_flow_identifier_columns": [
            column for column in flow_identifier_columns
        ],
        "timestamp_columns": timestamp_columns,
        "source_or_grouping_columns": grouping_columns,
        "selected_slice": {
            "start_row": start_row,
            "end_row": end_row,
            "row_count": len(selected),
            "label_distribution": selected_truth["label_counts"],
            "differs_from_full_distribution": (
                selected_truth["label_counts"]
                != full_truth["label_counts"]
            ),
        },
        "unavailable_fields": [
            field for field, available in (
                ("flow_identifier", bool(flow_identifier_columns)),
                ("timestamps", bool(timestamp_columns)),
                ("source_or_grouping", bool(grouping_columns)),
                ("invalid_label_count", False),
            ) if not available
        ],
        "label_column_lookup": lower_columns,
    }


def synthetic_fixtures() -> List[Dict[str, Any]]:
    """Return small deterministic records for the offline evaluation plan."""
    observation = {
        "packet_count": 100,
        "connection_count": 1,
        "average_flow_packets_per_second": 100.0,
        "average_flow_bytes_per_second": 100.0,
        "syn_flag_count": 0,
        "rst_flag_count": 0,
        "ack_flag_count": 1,
    }
    return [
        {
            "name": "clearly_benign_traffic",
            "kind": "classification",
            "label_counts": {"Benign": 1},
            "ground_truth_dominant_label": "Benign",
            "observation": observation,
            "expected_class": "BENIGN",
        },
        {
            "name": "clearly_malicious_traffic",
            "kind": "classification",
            "label_counts": {"DoS": 1},
            "ground_truth_dominant_label": "DoS",
            "observation": observation,
            "expected_class": "ATTACK",
        },
        {
            "name": "mixed_label_window",
            "kind": "classification",
            "label_counts": {"Benign": 1, "DoS": 2},
            "ground_truth_dominant_label": "DoS",
            "expected_class": "ATTACK",
        },
        {
            "name": "high_risk_low_severity",
            "kind": "routing",
            "state": {"severity": "MEDIUM", "risk_score": 55},
            "expected": "risk_assessment_required",
        },
        {
            "name": "severity_increases_after_response",
            "kind": "routing",
            "state": {
                "monitoring_result": {"severity_change": "INCREASED"},
                "severity": "MEDIUM",
                "risk_score": 20,
            },
            "expected": "response_agent",
        },
        {
            "name": "risk_increases_after_response",
            "kind": "routing",
            "state": {
                "monitoring_result": {"risk_increased": True},
                "severity": "MEDIUM",
                "risk_score": 40,
            },
            "expected": "response_agent",
        },
        {
            "name": "stable_risk_after_response",
            "kind": "routing",
            "state": {
                "monitoring_result": {
                    "severity_change": "STABLE",
                    "risk_increased": False,
                },
                "severity": "MEDIUM",
                "risk_score": 40,
            },
            "expected": "monitoring_agent",
        },
        {
            "name": "decreasing_severity_after_response",
            "kind": "routing",
            "state": {
                "monitoring_result": {
                    "severity_change": "DECREASED",
                    "risk_increased": False,
                },
                "severity": "MEDIUM",
                "risk_score": 20,
            },
            "expected": "monitoring_agent",
        },
        {
            "name": "ineffective_response_verification",
            "kind": "routing",
            "state": {
                "monitoring_result": {
                    "anomaly_detected": True,
                    "risk_increased": True,
                },
                "monitoring_count": 1,
                "max_monitoring_iterations": 5,
                "response_pending": False,
                "detection_history": [
                    {"monitoring_cycle": 1}
                ],
                "verification_result": {
                    "verification_status": "RESPONSE_INEFFECTIVE"
                },
            },
            "expected": "risk_agent",
        },
        {
            "name": "interrupted_execution",
            "kind": "completion",
            "state": {
                "monitoring_mode": "OFFLINE_DATASET",
                "monitoring_observations": [{}],
                "monitoring_count": 1,
                "interrupted": True,
                "run_status": "INTERRUPTED",
            },
            "expected": False,
        },
        {
            "name": "partially_processed_dataset",
            "kind": "completion",
            "state": {
                "monitoring_mode": "OFFLINE_DATASET",
                "monitoring_observations": [{}, {}],
                "monitoring_count": 1,
            },
            "expected": False,
        },
        {
            "name": "empty_observations",
            "kind": "completion",
            "state": {
                "monitoring_mode": "OFFLINE_DATASET",
                "monitoring_observations": [],
                "monitoring_count": 5,
            },
            "expected": False,
        },
        {
            "name": "iterative_monitoring_at_limit",
            "kind": "completion",
            "state": {
                "monitoring_mode": "LIVE",
                "monitoring_observations": [],
                "monitoring_count": 5,
                "max_monitoring_iterations": 5,
            },
            "expected": False,
        },
        {
            "name": "iterative_monitoring_early_termination",
            "kind": "completion",
            "state": {
                "monitoring_mode": "LIVE",
                "monitoring_observations": [],
                "monitoring_count": 4,
                "max_monitoring_iterations": 5,
            },
            "expected": False,
        },
    ]


def fixture_outcome(fixture: Dict[str, Any]) -> Any:
    """Evaluate routing/completion fixture behavior directly and deterministically."""
    kind = fixture["kind"]
    state = fixture.get("state", {})
    if kind == "completion":
        return monitoring_completed(state)
    if kind == "routing":
        if fixture["name"] == "ineffective_response_verification":
            return route_after_verification(state)
        if fixture["name"] == "high_risk_low_severity":
            return route_after_risk(state)
        return route_after_risk(state)
    return fixture.get("expected_class")
