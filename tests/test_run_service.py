import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import pandas as pd

from services.data_loader import load_network_data
from services.run_service import (
    RunRequest,
    RunResult,
    RunService,
)


class RunServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.dataset_directory = Path(
            self.temp_directory.name
        )
        self.dataset_path = (
            self.dataset_directory / "pilot.parquet"
        )
        self.dataset_path.touch()

    def tearDown(self):
        self.temp_directory.cleanup()

    def report(self, **overrides):
        report = {
            "dataset": "pilot.parquet",
            "pilot_start_row": 0,
            "pilot_end_row": 800,
            "pilot_batch_size": 100,
            "pilot_selection": (
                "FIXED_SEQUENTIAL_LABEL_INDEPENDENT"
            ),
            "run_status": "COMPLETED",
            "interruption_reason": None,
            "run_final_decision_code": (
                "NO_ACTIVE_THREAT_CONFIRMED"
            ),
            "monitoring_window_count": 8,
            "completed_window_count": 8,
            "partial_window_count": 0,
            "incomplete_window_count": 0,
            "rows": [
                {
                    "window": 1,
                    "window_status": "COMPLETED",
                    "overall_pipeline_prediction": "BENIGN",
                }
            ],
            "monitoring_metrics": {"evaluated_rows": 8},
            "llm_metrics": {"evaluated_rows": 0},
            "pipeline_metrics": {"evaluated_rows": 8},
            "graph_executions": 1,
        }
        report.update(overrides)
        return report

    def service(self, runner):
        return RunService(
            dataset_directory=self.dataset_directory,
            evaluator_runner=runner,
        )

    def test_run_validates_dataset_and_delegates_evaluator_contract(self):
        runner = Mock(return_value=self.report())
        graph_runner = object()
        service = self.service(runner)
        request = RunRequest("pilot.parquet")

        result = service.run(request, graph_runner=graph_runner)

        runner.assert_called_once_with(
            dataset_path=str(self.dataset_path.resolve()),
            start_row=0,
            end_row=800,
            batch_size=100,
            graph_runner=graph_runner,
            max_graph_executions=1,
        )
        self.assertIsInstance(result, RunResult)
        self.assertEqual(
            result.run_final_decision_code,
            "NO_ACTIVE_THREAT_CONFIRMED",
        )
        self.assertEqual(
            result.rows[0]["overall_pipeline_prediction"],
            "BENIGN",
        )
        self.assertEqual(result.graph_executions, 1)
        self.assertEqual(result.to_dict(), self.report())

    def test_interrupted_result_preserves_partial_and_incomplete_outcome(self):
        report = self.report(
            run_status="INTERRUPTED",
            interruption_reason="Gemini quota exceeded.",
            run_final_decision_code=None,
            completed_window_count=0,
            partial_window_count=1,
            incomplete_window_count=7,
            rows=[
                {
                    "window": 1,
                    "window_status": "PARTIAL",
                    "overall_pipeline_prediction": None,
                },
                {
                    "window": 2,
                    "window_status": "INCOMPLETE",
                    "overall_pipeline_prediction": None,
                },
            ],
            pipeline_metrics={"evaluated_rows": 0},
        )
        runner = Mock(return_value=report)

        result = self.service(runner).run(
            RunRequest("pilot.parquet")
        )

        self.assertEqual(result.run_status, "INTERRUPTED")
        self.assertEqual(
            result.interruption_reason,
            "Gemini quota exceeded.",
        )
        self.assertIsNone(result.run_final_decision_code)
        self.assertEqual(result.partial_window_count, 1)
        self.assertEqual(result.incomplete_window_count, 7)
        self.assertEqual(
            result.pipeline_metrics["evaluated_rows"],
            0,
        )

    def test_request_rejects_unsafe_or_invalid_configuration(self):
        invalid_requests = (
            {"dataset_identifier": ""},
            {"dataset_identifier": "nested/pilot.parquet"},
            {
                "dataset_identifier": "pilot.parquet",
                "start_row": -1,
            },
            {
                "dataset_identifier": "pilot.parquet",
                "end_row": 0,
            },
            {
                "dataset_identifier": "pilot.parquet",
                "batch_size": 0,
            },
            {
                "dataset_identifier": "pilot.parquet",
                "max_graph_executions": 2,
            },
        )
        for values in invalid_requests:
            with self.subTest(values=values):
                with self.assertRaises(
                    (TypeError, ValueError)
                ):
                    RunRequest(**values)

    def test_run_rejects_missing_or_unsupported_dataset(self):
        runner = Mock(return_value=self.report())
        service = self.service(runner)

        with self.assertRaises(FileNotFoundError):
            service.run(RunRequest("missing.parquet"))

        unsupported = self.dataset_directory / "pilot.txt"
        unsupported.touch()
        with self.assertRaises(ValueError):
            service.run(RunRequest("pilot.txt"))

    def test_parquet_dataset_is_resolved_and_loaded(self):
        dataset = self.dataset_directory / "sample.parquet"
        pd.DataFrame(
            {
                "Total Fwd Packets": [1],
                "Total Backward Packets": [2],
                "Flow Bytes/s": [3.0],
                "Flow Packets/s": [4.0],
                "SYN Flag Count": [0],
                "RST Flag Count": [0],
                "ACK Flag Count": [1],
                "Label": ["Benign"],
            }
        ).to_parquet(dataset, index=False)

        resolved = self.service(Mock()).resolve_dataset(
            dataset.name
        )
        loaded = load_network_data(str(resolved))

        self.assertEqual(resolved, dataset.resolve())
        self.assertEqual(loaded.shape, (1, 8))
        self.assertIn("Label", loaded.columns)

    def test_result_requires_the_complete_evaluator_shape(self):
        with self.assertRaises(ValueError):
            RunResult.from_evaluator_report(
                {"run_status": "COMPLETED"}
            )


if __name__ == "__main__":
    unittest.main()
