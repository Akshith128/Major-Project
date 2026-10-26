import unittest
from unittest.mock import patch

import pandas as pd

from core.graph import final_decision_agent
from evaluation.evaluator import (
    agent_observation,
    binary_class,
    binary_metrics,
    build_evaluation_rows,
    detector_metrics,
    overall_prediction,
    run_pilot,
    select_pilot_windows,
)


class EvaluatorTests(unittest.TestCase):
    def _windows(self, count=2):
        return [
            {
                "observation": {"packet_count": index},
                "ground_truth": (
                    "Benign" if index == 1 else "Attack"
                ),
                "label_counts": {
                    "Benign" if index == 1 else "Attack": 1
                },
            }
            for index in range(1, count + 1)
        ]

    def _complete_state(self):
        return {
            "severity_history": [
                {
                    "stage": "monitoring",
                    "cycle": 1,
                    "anomaly_detected": False,
                },
                {
                    "stage": "monitoring",
                    "cycle": 2,
                    "anomaly_detected": True,
                },
            ],
            "detection_history": [
                {
                    "monitoring_cycle": 2,
                    "raw_response": "THREAT_DETECTED: YES",
                }
            ],
            "final_decision_code": "ACTIVE_HIGH_RISK_THREAT",
        }

    def test_complete_stream_run_marks_all_windows_completed(self):
        class CompleteGraph:
            def stream(self, state, stream_mode):
                self.stream_mode = stream_mode
                yield {"severity_history": []}
                yield self.result

            result = None

        graph = CompleteGraph()
        graph.result = self._complete_state()
        with patch(
            "evaluation.evaluator.load_network_data",
            return_value=object(),
        ), patch(
            "evaluation.evaluator.select_pilot_windows",
            return_value=self._windows(),
        ):
            result = run_pilot(
                dataset_path="sample.parquet",
                graph_runner=graph,
            )

        self.assertEqual(graph.stream_mode, "values")
        self.assertEqual(result["run_status"], "COMPLETED")
        self.assertEqual(
            result["run_final_decision_code"],
            "ACTIVE_HIGH_RISK_THREAT",
        )
        self.assertEqual(result["completed_window_count"], 2)
        self.assertEqual(
            [row["window_status"] for row in result["rows"]],
            ["COMPLETED", "COMPLETED"],
        )
        self.assertEqual(
            result["pipeline_metrics"]["evaluated_rows"],
            2,
        )
        self.assertTrue(
            all(
                "final_decision_code" not in row
                for row in result["rows"]
            )
        )
        self.assertEqual(
            [
                row["overall_pipeline_prediction"]
                for row in result["rows"]
            ],
            ["BENIGN", "ATTACK"],
        )

    def test_quota_interruption_preserves_partial_and_incomplete_rows(self):
        class InterruptedGraph:
            def stream(self, state, stream_mode):
                yield {
                    "severity_history": [
                        {
                            "stage": "monitoring",
                            "cycle": 1,
                            "anomaly_detected": True,
                        }
                    ],
                    "detection_history": [
                        {
                            "monitoring_cycle": 1,
                            "raw_response": "THREAT_DETECTED: YES",
                        }
                    ],
                }
                raise RuntimeError(
                    "Gemini quota exceeded. Wait for the quota window "
                    "to reset before running again."
                )

        with patch(
            "evaluation.evaluator.load_network_data",
            return_value=object(),
        ), patch(
            "evaluation.evaluator.select_pilot_windows",
            return_value=self._windows(3),
        ):
            result = run_pilot(
                dataset_path="sample.parquet",
                graph_runner=InterruptedGraph(),
            )

        self.assertEqual(result["run_status"], "INTERRUPTED")
        self.assertIsNone(result["run_final_decision_code"])
        self.assertEqual(result["completed_window_count"], 0)
        self.assertEqual(result["partial_window_count"], 1)
        self.assertEqual(result["incomplete_window_count"], 2)
        self.assertEqual(
            [row["window_status"] for row in result["rows"]],
            ["PARTIAL", "INCOMPLETE", "INCOMPLETE"],
        )
        self.assertEqual(
            result["rows"][0]["monitoring_anomaly_prediction"],
            "ATTACK",
        )
        self.assertIsNone(
            result["rows"][0]["overall_pipeline_prediction"],
        )
        self.assertEqual(
            result["pipeline_metrics"]["evaluated_rows"],
            0,
        )
        self.assertEqual(
            result["llm_metrics"]["evaluated_rows"],
            1,
        )

    def test_quota_after_monitoring_marks_downstream_row_partial(self):
        class DownstreamInterruptedGraph:
            def stream(self, state, stream_mode):
                yield {
                    "severity_history": [
                        {
                            "stage": "monitoring",
                            "cycle": 1,
                            "anomaly_detected": True,
                        }
                    ]
                }
                raise RuntimeError(
                    "Gemini quota exceeded. Wait for the quota window "
                    "to reset before running again."
                )

        with patch(
            "evaluation.evaluator.load_network_data",
            return_value=object(),
        ), patch(
            "evaluation.evaluator.select_pilot_windows",
            return_value=self._windows(),
        ):
            result = run_pilot(
                dataset_path="sample.parquet",
                graph_runner=DownstreamInterruptedGraph(),
            )

        self.assertEqual(
            result["rows"][0]["window_status"],
            "PARTIAL",
        )
        self.assertIsNone(
            result["rows"][0]["overall_pipeline_prediction"],
        )
        self.assertEqual(
            result["monitoring_metrics"]["evaluated_rows"],
            1,
        )
        self.assertEqual(
            result["pipeline_metrics"]["evaluated_rows"],
            0,
        )

    def test_interrupted_run_does_not_infer_prior_cycle_completion(
        self
    ):
        class LaterCycleInterruptedGraph:
            def stream(self, state, stream_mode):
                yield {
                    "severity_history": [
                        {
                            "stage": "monitoring",
                            "cycle": 1,
                            "anomaly_detected": False,
                        },
                        {
                            "stage": "monitoring",
                            "cycle": 2,
                            "anomaly_detected": True,
                        },
                    ]
                }
                raise RuntimeError(
                    "Gemini quota exceeded. Wait for the quota window "
                    "to reset before running again."
                )

        with patch(
            "evaluation.evaluator.load_network_data",
            return_value=object(),
        ), patch(
            "evaluation.evaluator.select_pilot_windows",
            return_value=self._windows(3),
        ):
            result = run_pilot(
                dataset_path="sample.parquet",
                graph_runner=LaterCycleInterruptedGraph(),
            )

        self.assertEqual(
            [row["window_status"] for row in result["rows"]],
            ["PARTIAL", "PARTIAL", "INCOMPLETE"],
        )
        self.assertIsNone(
            result["rows"][0]["overall_pipeline_prediction"],
        )
        self.assertIsNone(
            result["rows"][1]["overall_pipeline_prediction"],
        )
        self.assertEqual(
            result["pipeline_metrics"]["evaluated_rows"],
            0,
        )

    def test_complete_status_without_final_decision_is_not_fully_complete(
        self
    ):
        class NonTerminalGraph:
            def stream(self, state, stream_mode):
                yield {
                    "severity_history": [
                        {
                            "stage": "monitoring",
                            "cycle": 1,
                            "anomaly_detected": False,
                        },
                        {
                            "stage": "monitoring",
                            "cycle": 2,
                            "anomaly_detected": True,
                        },
                    ]
                }

        with patch(
            "evaluation.evaluator.load_network_data",
            return_value=object(),
        ), patch(
            "evaluation.evaluator.select_pilot_windows",
            return_value=self._windows(2),
        ):
            result = run_pilot(
                dataset_path="sample.parquet",
                graph_runner=NonTerminalGraph(),
            )

        self.assertEqual(result["run_status"], "INCOMPLETE")
        self.assertIsNone(result["run_final_decision_code"])
        self.assertEqual(
            [row["window_status"] for row in result["rows"]],
            ["INCOMPLETE", "INCOMPLETE"],
        )
        self.assertEqual(
            result["pipeline_metrics"]["evaluated_rows"],
            0,
        )

    def test_completed_run_invalid_final_decision_is_not_reported(self):
        missing = object()

        class InvalidDecisionGraph:
            def __init__(self, final_decision):
                self.final_decision = final_decision

            def stream(self, state, stream_mode):
                result = {
                    "severity_history": [
                        {
                            "stage": "monitoring",
                            "cycle": 1,
                            "anomaly_detected": False,
                        }
                    ]
                }
                if self.final_decision is not missing:
                    result["final_decision_code"] = (
                        self.final_decision
                    )
                yield result

        for final_decision in (missing, None, "", "   "):
            with self.subTest(final_decision=final_decision), patch(
                "evaluation.evaluator.load_network_data",
                return_value=object(),
            ), patch(
                "evaluation.evaluator.select_pilot_windows",
                return_value=self._windows(1),
            ):
                result = run_pilot(
                    dataset_path="sample.parquet",
                    graph_runner=InvalidDecisionGraph(
                        final_decision,
                    ),
                )

            self.assertEqual(result["run_status"], "INCOMPLETE")
            self.assertIsNone(
                result["run_final_decision_code"],
            )
            self.assertEqual(
                result["rows"][0]["window_status"],
                "INCOMPLETE",
            )
            self.assertIsNone(
                result["rows"][0]["overall_pipeline_prediction"],
            )

    def test_interrupted_run_does_not_report_partial_final_decision(self):
        class InterruptedGraph:
            state = None

            def stream(self, state, stream_mode):
                self.state = {
                    **state,
                    "monitoring_count": 1,
                    "monitoring_mode": "LIVE",
                    "monitoring_observations": [],
                    "max_monitoring_iterations": 1,
                    "severity_history": [
                        {
                            "stage": "monitoring",
                            "cycle": 1,
                            "anomaly_detected": True,
                        }
                    ],
                    "final_decision_code": (
                        "ACTIVE_HIGH_RISK_THREAT"
                    ),
                }
                yield self.state
                raise RuntimeError(
                    "Gemini quota exceeded. Wait for the quota window "
                    "to reset before running again."
                )

        with patch(
            "evaluation.evaluator.load_network_data",
            return_value=object(),
        ), patch(
            "evaluation.evaluator.select_pilot_windows",
            return_value=self._windows(1),
        ):
            graph = InterruptedGraph()
            result = run_pilot(
                dataset_path="sample.parquet",
                graph_runner=graph,
            )

        self.assertEqual(result["run_status"], "INTERRUPTED")
        self.assertIsNone(result["run_final_decision_code"])
        self.assertTrue(graph.state["interrupted"])
        self.assertEqual(
            graph.state["run_status"],
            "INTERRUPTED",
        )
        self.assertIn(
            "Gemini quota exceeded.",
            graph.state["interruption_reason"],
        )
        graph_decision = final_decision_agent(
            graph.state
        )
        self.assertEqual(
            graph_decision["status"],
            "incomplete",
        )
        self.assertIsNone(
            graph_decision["final_decision_code"]
        )

    def test_completed_run_decision_is_run_level_only(self):
        class CompletedGraph:
            def stream(self, state, stream_mode):
                yield {
                    "severity_history": [
                        {
                            "stage": "monitoring",
                            "cycle": 1,
                            "anomaly_detected": False,
                        }
                    ],
                    "final_decision_code": (
                        "NO_ACTIVE_THREAT_CONFIRMED"
                    ),
                }

        with patch(
            "evaluation.evaluator.load_network_data",
            return_value=object(),
        ), patch(
            "evaluation.evaluator.select_pilot_windows",
            return_value=self._windows(1),
        ):
            result = run_pilot(
                dataset_path="sample.parquet",
                graph_runner=CompletedGraph(),
            )

        self.assertEqual(result["run_status"], "COMPLETED")
        self.assertEqual(
            result["run_final_decision_code"],
            "NO_ACTIVE_THREAT_CONFIRMED",
        )
        self.assertNotIn(
            "final_decision_code",
            result["rows"][0],
        )
        self.assertEqual(
            result["rows"][0]["overall_pipeline_prediction"],
            "BENIGN",
        )

    def test_unrelated_stream_exception_propagates(self):
        class BrokenGraph:
            def stream(self, state, stream_mode):
                raise ValueError("unexpected failure")
                yield

        with patch(
            "evaluation.evaluator.load_network_data",
            return_value=object(),
        ), patch(
            "evaluation.evaluator.select_pilot_windows",
            return_value=self._windows(),
        ), self.assertRaises(ValueError):
            run_pilot(
                dataset_path="sample.parquet",
                graph_runner=BrokenGraph(),
            )

    def test_binary_label_mapping(self):
        self.assertEqual(binary_class("Benign"), "BENIGN")
        self.assertEqual(binary_class("Brute Force -Web"), "ATTACK")

    def test_mixed_window_uses_dominant_label(self):
        windows = [
            {
                "observation": {"packet_count": 1},
                "ground_truth": "Brute Force -Web",
                "label_counts": {
                    "Brute Force -Web": 6,
                    "Benign": 4,
                },
            }
        ]
        rows = build_evaluation_rows("sample.parquet", windows)
        self.assertEqual(
            rows[0]["ground_truth_dominant_label"],
            "Brute Force -Web",
        )
        self.assertEqual(rows[0]["ground_truth_binary_class"], "ATTACK")

    def test_binary_confusion_counts_and_metrics(self):
        rows = [
            {"ground_truth_binary_class": "ATTACK", "prediction": "ATTACK"},
            {"ground_truth_binary_class": "BENIGN", "prediction": "BENIGN"},
            {"ground_truth_binary_class": "BENIGN", "prediction": "ATTACK"},
            {"ground_truth_binary_class": "ATTACK", "prediction": "BENIGN"},
        ]
        metrics = binary_metrics(rows, "prediction")
        self.assertEqual(
            {key: metrics[key] for key in ("TP", "TN", "FP", "FN")},
            {"TP": 1, "TN": 1, "FP": 1, "FN": 1},
        )
        self.assertEqual(metrics["accuracy"], 0.5)
        self.assertEqual(metrics["precision"], 0.5)
        self.assertEqual(metrics["recall"], 0.5)
        self.assertEqual(metrics["f1"], 0.5)
        self.assertEqual(metrics["false_positive_rate"], 0.5)
        self.assertEqual(metrics["evaluated_rows"], 4)
        self.assertEqual(metrics["total_rows"], 4)
        self.assertEqual(metrics["missing_predictions"], 0)

    def test_zero_denominators_are_safe(self):
        metrics = binary_metrics([], "prediction")
        self.assertEqual(metrics["accuracy"], 0.0)
        self.assertEqual(metrics["precision"], 0.0)
        self.assertEqual(metrics["recall"], 0.0)
        self.assertEqual(metrics["f1"], 0.0)
        self.assertEqual(metrics["false_positive_rate"], 0.0)
        self.assertEqual(metrics["evaluated_rows"], 0)
        self.assertEqual(metrics["total_rows"], 0)
        self.assertEqual(metrics["missing_predictions"], 0)

    def test_missing_detector_uses_monitoring_fallback(self):
        self.assertEqual(
            overall_prediction(True, None),
            "ATTACK",
        )
        self.assertEqual(
            overall_prediction(False, None),
            "BENIGN",
        )
        windows = [
            {
                "observation": {"packet_count": 1},
                "ground_truth": "Benign",
                "label_counts": {"Benign": 1},
            }
        ]
        rows = build_evaluation_rows(
            "sample.parquet",
            windows,
            {
                "severity_history": [
                    {
                        "stage": "monitoring",
                        "cycle": 1,
                        "anomaly_detected": True,
                        "severity": "MEDIUM",
                        "risk_score": 40,
                    }
                ]
            },
        )
        self.assertFalse(rows[0]["llm_detection_invoked"])
        self.assertIsNone(rows[0]["llm_detection_prediction"])
        self.assertEqual(
            rows[0]["overall_pipeline_prediction"],
            None,
        )
        metrics = binary_metrics(
            [
                {
                    "ground_truth_binary_class": "BENIGN",
                    "prediction": None,
                }
            ],
            "prediction",
        )
        self.assertEqual(metrics["evaluated_rows"], 0)
        self.assertEqual(metrics["total_rows"], 1)
        self.assertEqual(metrics["missing_predictions"], 1)

    def test_detector_metrics_exclude_missing_and_invalid_predictions(self):
        rows = [
            {
                "ground_truth_binary_class": "ATTACK",
                "llm_detection_invoked": True,
                "llm_detection_prediction": "ATTACK",
                "overall_pipeline_prediction": "ATTACK",
            },
            {
                "ground_truth_binary_class": "BENIGN",
                "llm_detection_invoked": True,
                "llm_detection_prediction": None,
                "overall_pipeline_prediction": "BENIGN",
            },
            {
                "ground_truth_binary_class": "BENIGN",
                "llm_detection_invoked": False,
                "llm_detection_prediction": None,
                "overall_pipeline_prediction": "BENIGN",
            },
        ]
        metrics = detector_metrics(rows)
        self.assertEqual(metrics["detector_invocations"], 2)
        self.assertEqual(metrics["invalid_or_unparseable_responses"], 1)
        self.assertEqual(metrics["fallback_predictions"], 2)
        self.assertEqual(metrics["evaluated_rows"], 1)
        self.assertEqual(metrics["missing_predictions"], 0)
        self.assertEqual(metrics["accuracy"], 1.0)

    def test_ground_truth_is_not_in_agent_observation(self):
        window = {
            "observation": {
                "packet_count": 10,
                "average_flow_packets_per_second": 2,
            },
            "ground_truth": "Attack",
            "label_counts": {"Attack": 1},
        }
        observation = agent_observation(window)
        self.assertEqual(observation, window["observation"])
        self.assertNotIn("ground_truth", observation)
        self.assertNotIn("label_counts", observation)

    def test_pilot_selection_is_reproducible_and_limited(self):
        rows = []
        for index in range(12):
            rows.append(
                {
                    "Total Fwd Packets": 1,
                    "Total Backward Packets": 1,
                    "Flow Bytes/s": 1,
                    "Flow Packets/s": 1,
                    "SYN Flag Count": 0,
                    "RST Flag Count": 0,
                    "ACK Flag Count": 0,
                    "Label": "Benign",
                }
            )
        first = select_pilot_windows(
            pd.DataFrame(rows),
            start_row=2,
            end_row=10,
            batch_size=2,
        )
        second = select_pilot_windows(
            pd.DataFrame(rows),
            start_row=2,
            end_row=10,
            batch_size=2,
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first), 4)

    def test_pilot_allows_only_one_graph_execution(self):
        with self.assertRaises(ValueError):
            run_pilot(
                dataset_path="not_loaded.parquet",
                max_graph_executions=2,
            )
if __name__ == "__main__":
    unittest.main()
