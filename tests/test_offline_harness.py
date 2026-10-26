import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from core.graph import final_decision_agent
from evaluation.offline_harness import (
    evaluate_windows,
    fixture_outcome,
    inspect_dataset,
    replay_recorded_detector_outputs,
    replay_dataset_slice,
    serialize_result,
    synthetic_fixtures,
)
from services.data_loader import (
    create_monitoring_observations,
    get_ground_truth,
    load_network_data,
)


class OfflineHarnessTests(unittest.TestCase):
    DATASET = Path(
        "data/raw/"
        "Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet"
    )

    def recorded_outputs(self, provenance="synthetic_test"):
        rows = [
            (1, 1000, 1100, False, None, None),
            (2, 1100, 1200, True, "ATTACK", "recorded attack"),
            (3, 1200, 1300, True, None, "unparseable"),
            (4, 1300, 1400, True, "ATTACK", "recorded attack"),
            (5, 1400, 1405, False, None, None),
        ]
        return [
            {
                "dataset": self.DATASET.name,
                "window": window,
                "row_start": start,
                "row_end": end,
                "detector_invoked": invoked,
                "raw_output": raw,
                "parsed_prediction": prediction,
                "source": "offline-test-fixture",
                "provenance": provenance,
                "invocation_reason": "synthetic_record",
            }
            for (
                window,
                start,
                end,
                invoked,
                prediction,
                raw,
            ) in rows
        ]

    def test_synthetic_fixtures_cover_required_scenarios(self):
        fixtures = synthetic_fixtures()
        self.assertEqual(len(fixtures), 14)
        names = {fixture["name"] for fixture in fixtures}
        self.assertIn("decreasing_severity_after_response", names)
        self.assertIn("iterative_monitoring_at_limit", names)

        outcomes = {
            fixture["name"]: fixture_outcome(fixture)
            for fixture in fixtures
            if fixture["kind"] != "classification"
        }
        self.assertFalse(outcomes["interrupted_execution"])
        self.assertFalse(outcomes["partially_processed_dataset"])
        self.assertFalse(outcomes["empty_observations"])
        self.assertFalse(outcomes["iterative_monitoring_at_limit"])
        self.assertFalse(
            outcomes["iterative_monitoring_early_termination"]
        )
        self.assertEqual(
            outcomes["severity_increases_after_response"],
            "response_agent",
        )
        self.assertEqual(
            outcomes["risk_increases_after_response"],
            "response_agent",
        )
        self.assertEqual(
            outcomes["stable_risk_after_response"],
            "monitoring_agent",
        )
        self.assertEqual(
            outcomes["decreasing_severity_after_response"],
            "monitoring_agent",
        )
        self.assertEqual(
            outcomes["ineffective_response_verification"],
            "risk_agent",
        )

    def test_metrics_use_separate_populations_and_expose_missing(self):
        result = evaluate_windows(
            [
                {
                    "ground_truth_dominant_label": "Benign",
                    "label_counts": {"Benign": 1},
                    "monitoring_anomaly_prediction": "BENIGN",
                    "llm_detection_invoked": False,
                    "llm_detection_prediction": None,
                    "overall_pipeline_prediction": "BENIGN",
                    "fallback_source": "monitoring",
                },
                {
                    "ground_truth_dominant_label": "DoS",
                    "label_counts": {"DoS": 1},
                    "monitoring_anomaly_prediction": "ATTACK",
                    "llm_detection_invoked": True,
                    "llm_detection_prediction": "ATTACK",
                    "overall_pipeline_prediction": "ATTACK",
                },
                {
                    "ground_truth_dominant_label": "DoS",
                    "label_counts": {"DoS": 1},
                    "monitoring_anomaly_prediction": None,
                    "llm_detection_invoked": True,
                    "llm_detection_prediction": None,
                    "overall_pipeline_prediction": None,
                    "window_status": "INCOMPLETE",
                },
            ],
            run_status="INTERRUPTED",
            run_final_decision_code="ACTIVE_HIGH_RISK_THREAT",
            interruption_reason="quota",
        )

        self.assertEqual(
            result["metrics"]["monitoring"]["evaluated_rows"],
            2,
        )
        self.assertEqual(
            result["metrics"]["detector"]["invoked_rows"],
            2,
        )
        self.assertEqual(
            result["metrics"]["detector"]["evaluated_rows"],
            1,
        )
        self.assertEqual(
            result["metrics"]["detector"]["missing_predictions"],
            2,
        )
        self.assertEqual(
            result["metrics"]["overall_pipeline"]["evaluated_rows"],
            2,
        )
        self.assertEqual(
            result["metrics"]["overall_pipeline"]["missing_predictions"],
            1,
        )
        self.assertEqual(
            result["metrics"]["overall_pipeline"]["total_window_population"],
            3,
        )
        self.assertEqual(
            result["prediction_availability"]["fallback_predictions"],
            1,
        )
        self.assertIsNone(
            result["run"]["run_final_decision_code"]
        )
        self.assertEqual(result["run"]["incomplete_window_count"], 1)

    def test_result_serialization_and_label_isolation(self):
        result = evaluate_windows(
            [
                {
                    "ground_truth_dominant_label": "Benign",
                    "label_counts": {"Benign": 1},
                    "observation": {"packet_count": 1},
                    "monitoring_anomaly_prediction": "BENIGN",
                    "overall_pipeline_prediction": "BENIGN",
                }
            ],
            dataset="synthetic.csv",
        )
        encoded = serialize_result(result)
        decoded = json.loads(encoded)
        self.assertEqual(decoded["evaluation_configuration"]["dataset"], "synthetic.csv")
        self.assertNotIn(
            "ground_truth_dominant_label",
            decoded["evaluation_configuration"],
        )
        self.assertEqual(
            decoded["windows"][0]["ground_truth_binary_class"],
            "BENIGN",
        )

    def test_ground_truth_reuses_existing_dominant_label_semantics(self):
        dataframe = pd.DataFrame(
            {
                "Label": [
                    " DoS ",
                    "PortScan",
                    None,
                    "DoS",
                ]
            }
        )
        truth = get_ground_truth(dataframe)
        self.assertEqual(truth["ground_truth"], "DoS")
        self.assertEqual(
            truth["label_counts"],
            {"DoS": 2, "PortScan": 1, "Unknown": 1},
        )
        self.assertEqual(
            truth["attack_flow_count"],
            4,
        )

        tie_truth = get_ground_truth(
            pd.DataFrame({"Label": ["DoS", "PortScan"]})
        )
        self.assertEqual(tie_truth["ground_truth"], "DoS")

        empty_truth = get_ground_truth(
            pd.DataFrame({"Label": []})
        )
        self.assertEqual(empty_truth["ground_truth"], "Benign")

    def test_inspection_reports_distribution_duplicates_and_available_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.csv"
            dataframe = pd.DataFrame(
                [
                    {
                        "Label": "Benign",
                        "Flow ID": "a",
                        "Timestamp": "2026-01-01",
                    },
                    {
                        "Label": " DoS ",
                        "Flow ID": "b",
                        "Timestamp": "2026-01-02",
                    },
                    {
                        "Label": "Benign",
                        "Flow ID": "a",
                        "Timestamp": "2026-01-01",
                    },
                ]
            )
            dataframe.to_csv(path, index=False)
            report = inspect_dataset(
                str(path),
                start_row=0,
                end_row=1,
            )

        self.assertEqual(report["row_count"], 3)
        self.assertEqual(report["column_count"], 3)
        self.assertEqual(report["exact_duplicate_row_count"], 1)
        self.assertEqual(report["binary_label_distribution"]["ATTACK"], 1)
        self.assertTrue(
            report["selected_slice"]["differs_from_full_distribution"]
        )
        self.assertEqual(
            report["likely_flow_identifier_columns"],
            ["Flow ID"],
        )
        self.assertEqual(
            report["timestamp_columns"],
            ["Timestamp"],
        )

    def test_graph_level_incomplete_state_has_no_successful_decision(self):
        state = {
            "monitoring_mode": "OFFLINE_DATASET",
            "monitoring_observations": [{}],
            "monitoring_count": 1,
            "interrupted": True,
            "run_status": "INTERRUPTED",
            "severity": "LOW",
            "risk_score": 0,
        }
        decision = final_decision_agent(state)
        self.assertEqual(decision["status"], "incomplete")
        self.assertIsNone(decision["final_decision_code"])

    @unittest.skipUnless(
        Path(
            "data/raw/"
            "Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet"
        ).is_file(),
        "local Botnet CIC-IDS2018 dataset is unavailable",
    )
    def test_fixed_botnet_slice_replays_with_actual_window_contract(self):
        calls = []

        def mocked_agent(observation, window_index):
            calls.append((observation, window_index))
            self.assertNotIn("Label", observation)
            self.assertNotIn("ground_truth", observation)
            self.assertNotIn("label_counts", observation)
            return {
                "monitoring_anomaly_prediction": (
                    "ATTACK" if window_index == 2 else "BENIGN"
                ),
                "detector_invoked": window_index == 2,
                "detector_invocation_reason": "test",
                "detector_prediction": (
                    "ATTACK" if window_index == 2 else None
                ),
                "detector_raw_response": (
                    "MOCK" if window_index == 2 else None
                ),
                "overall_pipeline_prediction": (
                    "ATTACK" if window_index == 2 else "BENIGN"
                ),
                "fallback_source": (
                    None if window_index == 2 else "monitoring"
                ),
            }

        result = replay_dataset_slice(
            str(self.DATASET),
            start_row=1000,
            end_row=1405,
            batch_size=100,
            mock_agent=mocked_agent,
            mock_configuration_id="test-mock-v1",
        )

        self.assertEqual(len(calls), 5)
        self.assertEqual(
            result["evaluation_configuration"]["dataset_format"],
            "parquet",
        )
        self.assertEqual(
            result["evaluation_configuration"]["label_column"],
            "Label",
        )
        self.assertEqual(
            result["evaluation_configuration"]["full_selected_label_counts"],
            {"Bot": 205, "Benign": 200},
        )
        self.assertEqual(
            [
                (
                    row["row_start"],
                    row["row_end"],
                    row["window_flow_count"],
                    row["ground_truth_dominant_label"],
                )
                for row in result["windows"]
            ],
            [
                (1000, 1100, 100, "Benign"),
                (1100, 1200, 100, "Bot"),
                (1200, 1300, 100, "Bot"),
                (1300, 1400, 100, "Bot"),
                (1400, 1405, 5, "Bot"),
            ],
        )
        self.assertTrue(result["windows"][-1]["partial_final_window"])
        self.assertEqual(
            result["prediction_availability"]["total_windows"],
            5,
        )
        self.assertEqual(
            result["run"]["completed_window_count"],
            5,
        )
        self.assertEqual(
            result["metrics"]["completed_pipeline"]["total_window_population"],
            4,
        )
        self.assertEqual(
            result["metrics"]["completed_pipeline"]["evaluated_rows"],
            4,
        )

        selected = load_network_data(str(self.DATASET)).iloc[1000:1405]
        expected_windows = create_monitoring_observations(
            selected,
            batch_size=100,
        )
        for row, expected in zip(
            result["windows"],
            expected_windows,
        ):
            self.assertEqual(
                row["label_counts"],
                expected["label_counts"],
            )
            self.assertEqual(
                row["ground_truth_dominant_label"],
                expected["ground_truth"],
            )
            self.assertEqual(
                row["ground_truth_binary_class"],
                (
                    "BENIGN"
                    if expected["ground_truth"].lower() == "benign"
                    else "ATTACK"
                ),
            )
            self.assertEqual(
                row["window_flow_count"],
                expected["dataset_flow_count"],
            )

    @unittest.skipUnless(
        Path(
            "data/raw/"
            "Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet"
        ).is_file(),
        "local Botnet CIC-IDS2018 dataset is unavailable",
    )
    def test_replay_is_repeatable_and_interruption_is_explicit(self):
        kwargs = {
            "dataset_path": str(self.DATASET),
            "start_row": 1000,
            "end_row": 1405,
            "batch_size": 100,
        }
        first = replay_dataset_slice(**kwargs)
        second = replay_dataset_slice(**kwargs)
        self.assertEqual(
            serialize_result(first),
            serialize_result(second),
        )

        interrupted = replay_dataset_slice(
            **kwargs,
            run_status="INTERRUPTED",
            interruption_reason="deterministic test interruption",
            interrupt_after_window=2,
        )
        self.assertEqual(
            [row["window_status"] for row in interrupted["windows"]],
            [
                "COMPLETED",
                "PARTIAL",
                "INCOMPLETE",
                "INCOMPLETE",
                "INCOMPLETE",
            ],
        )
        self.assertIsNone(
            interrupted["run"]["run_final_decision_code"]
        )
        self.assertEqual(
            interrupted["run"]["partial_window_count"],
            1,
        )
        self.assertEqual(
            interrupted["run"]["incomplete_window_count"],
            3,
        )
        self.assertEqual(
            interrupted["metrics"]["overall_pipeline"]["missing_predictions"],
            4,
        )

    @unittest.skipUnless(
        Path(
            "data/raw/"
            "Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet"
        ).is_file(),
        "local Botnet CIC-IDS2018 dataset is unavailable",
    )
    def test_recorded_outputs_match_exact_windows_and_preserve_provenance(self):
        records = self.recorded_outputs()
        result = replay_recorded_detector_outputs(
            str(self.DATASET),
            start_row=1000,
            end_row=1405,
            batch_size=100,
            recorded_outputs=records,
            expected_provenance="synthetic_test",
        )
        self.assertEqual(
            result["evaluation_configuration"][
                "recorded_output_provenance"
            ],
            "synthetic_test",
        )
        self.assertEqual(
            [row["detector_output_provenance"] for row in result["windows"]],
            ["synthetic_test"] * 5,
        )
        self.assertEqual(
            [row["llm_detection_prediction"] for row in result["windows"]],
            [None, "ATTACK", None, "ATTACK", None],
        )
        self.assertEqual(
            [
                row["detector_prediction_status"]
                for row in result["windows"]
            ],
            ["NOT_INVOKED", "PARSED", "UNPARSEABLE", "PARSED", "NOT_INVOKED"],
        )
        self.assertEqual(
            result["metrics"]["detector"]["evaluated_rows"],
            2,
        )
        self.assertEqual(
            result["metrics"]["detector"]["missing_predictions"],
            3,
        )
        self.assertEqual(
            result["metrics"]["detector"]["invalid_or_unparseable_responses"],
            1,
        )
        self.assertEqual(
            result["metrics"]["detector"]["not_invoked_rows"],
            2,
        )
        self.assertEqual(
            result["metrics"]["detector"]["unparseable_rows"],
            1,
        )
        self.assertEqual(
            result["metrics"]["detector"]["invoked_missing_rows"],
            0,
        )
        self.assertEqual(
            result["prediction_availability"]["fallback_predictions"],
            3,
        )
        self.assertEqual(
            serialize_result(result),
            serialize_result(
                replay_recorded_detector_outputs(
                    str(self.DATASET),
                    start_row=1000,
                    end_row=1405,
                    batch_size=100,
                    recorded_outputs=self.recorded_outputs(),
                    expected_provenance="synthetic_test",
                )
            ),
        )

    @unittest.skipUnless(
        Path(
            "data/raw/"
            "Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet"
        ).is_file(),
        "local Botnet CIC-IDS2018 dataset is unavailable",
    )
    def test_recorded_replay_rejects_ambiguous_or_label_derived_records(self):
        records = self.recorded_outputs()
        with self.assertRaises(ValueError):
            replay_recorded_detector_outputs(
                str(self.DATASET),
                start_row=1000,
                end_row=1405,
                batch_size=100,
                recorded_outputs=records + [records[0]],
                expected_provenance="synthetic_test",
            )

        invalid = self.recorded_outputs()
        invalid[0] = {
            **invalid[0],
            "ground_truth_binary_class": "BENIGN",
        }
        with self.assertRaises(ValueError):
            replay_recorded_detector_outputs(
                str(self.DATASET),
                start_row=1000,
                end_row=1405,
                batch_size=100,
                recorded_outputs=invalid,
                expected_provenance="synthetic_test",
            )

        invalid = self.recorded_outputs()
        invalid[0] = {
            **invalid[0],
            "derived_from_ground_truth": True,
        }
        with self.assertRaises(ValueError):
            replay_recorded_detector_outputs(
                str(self.DATASET),
                start_row=1000,
                end_row=1405,
                batch_size=100,
                recorded_outputs=invalid,
                expected_provenance="synthetic_test",
            )

    @unittest.skipUnless(
        Path(
            "data/raw/"
            "Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet"
        ).is_file(),
        "local Botnet CIC-IDS2018 dataset is unavailable",
    )
    def test_recorded_replay_rejects_invalid_prediction_and_missing_window(self):
        invalid = self.recorded_outputs()
        invalid[1] = {
            **invalid[1],
            "parsed_prediction": "MAYBE",
        }
        with self.assertRaises(ValueError):
            replay_recorded_detector_outputs(
                str(self.DATASET),
                start_row=1000,
                end_row=1405,
                batch_size=100,
                recorded_outputs=invalid,
                expected_provenance="synthetic_test",
            )

        missing = self.recorded_outputs()[:-1]
        with self.assertRaises(ValueError):
            replay_recorded_detector_outputs(
                str(self.DATASET),
                start_row=1000,
                end_row=1405,
                batch_size=100,
                recorded_outputs=missing,
                expected_provenance="synthetic_test",
            )

    def test_recorded_provenance_is_not_real_without_explicit_genuine_input(self):
        records = self.recorded_outputs()
        with self.assertRaises(ValueError):
            replay_recorded_detector_outputs(
                str(self.DATASET),
                start_row=1000,
                end_row=1405,
                batch_size=100,
                recorded_outputs=records,
                expected_provenance="model_generated",
            )

    def test_genuine_record_schema_requires_capture_metadata(self):
        records = self.recorded_outputs(provenance="genuine_recorded")
        records[0]["captured_at"] = "2026-10-12T10:00:00+00:00"
        records[1]["captured_at"] = "2026-10-12T10:00:01+00:00"
        records[2]["captured_at"] = "2026-10-12T10:00:02+00:00"
        records[3]["captured_at"] = "2026-10-12T10:00:03+00:00"
        records[4]["captured_at"] = "2026-10-12T10:00:04+00:00"
        result = replay_recorded_detector_outputs(
            str(self.DATASET),
            start_row=1000,
            end_row=1405,
            batch_size=100,
            recorded_outputs=records,
            expected_provenance="genuine_recorded",
        )
        self.assertEqual(
            result["windows"][0]["detector_output_captured_at"],
            "2026-10-12T10:00:00+00:00",
        )
        invalid = self.recorded_outputs(provenance="genuine_recorded")
        with self.assertRaises(ValueError):
            replay_recorded_detector_outputs(
                str(self.DATASET),
                start_row=1000,
                end_row=1405,
                batch_size=100,
                recorded_outputs=invalid,
                expected_provenance="genuine_recorded",
            )


if __name__ == "__main__":
    unittest.main()
