import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from fastapi.testclient import TestClient

from api.app import create_app
from services.run_service import RunService


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.dataset_directory = Path(self.temp_directory.name)
        self.dataset_path = (
            self.dataset_directory / "pilot.parquet"
        )
        self.dataset_path.touch()
        self.runner = Mock(return_value=self.report())
        self.service = RunService(
            dataset_directory=self.dataset_directory,
            evaluator_runner=self.runner,
        )
        self.run_store_path = self.dataset_directory / "runs.json"
        self.client = TestClient(
            create_app(
                run_service=self.service,
                run_store_path=self.run_store_path,
            )
        )

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
            "run_final_decision_code": "THREAT_MITIGATED",
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
            "llm_metrics": {"evaluated_rows": 4},
            "pipeline_metrics": {"evaluated_rows": 8},
            "graph_executions": 1,
        }
        report.update(overrides)
        return report

    def test_health_and_dataset_endpoints(self):
        health = self.client.get("/api/v1/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json(), {"status": "ok"})

        with unittest.mock.patch(
            "api.app.load_network_data",
            return_value=type(
                "Frame",
                (),
                {
                    "columns": ["Label", "Flow Bytes/s"],
                    "__len__": lambda self: 10,
                },
            )(),
        ):
            datasets = self.client.get("/api/v1/datasets")
        self.assertEqual(datasets.status_code, 200)
        self.assertEqual(
            datasets.json()["datasets"][0]["dataset_id"],
            "pilot.parquet",
        )
        self.assertTrue(
            datasets.json()["datasets"][0]["has_labels"]
        )

    def test_frontend_origins_are_allowed_by_cors(self):
        response = self.client.options(
            "/api/v1/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["access-control-allow-origin"],
            "http://localhost:3000",
        )

    def test_schema_reuses_safe_dataset_resolution(self):
        frame = type(
            "Frame",
            (),
            {
                "columns": ["Label", "Flow Bytes/s"],
                "__len__": lambda self: 10,
                "__getitem__": lambda self, key: type(
                    "Column",
                    (),
                    {"dtype": "float64"},
                )(),
            },
        )()
        with unittest.mock.patch(
            "api.app.load_network_data",
            return_value=frame,
        ):
            response = self.client.get(
                "/api/v1/datasets/pilot.parquet/schema"
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["row_count"], 10)

        unsafe = self.client.get(
            "/api/v1/datasets/..%2Fpilot.parquet/schema"
        )
        self.assertIn(unsafe.status_code, (400, 404))

    def test_run_and_result_keep_run_decision_separate(self):
        response = self.client.post(
            "/api/v1/runs",
            json={"dataset_id": "pilot.parquet"},
        )
        self.assertEqual(response.status_code, 201)
        run = response.json()
        self.assertEqual(
            run["run_final_decision_code"],
            "THREAT_MITIGATED",
        )
        run_id = run["run_id"]

        result = self.client.get(
            f"/api/v1/runs/{run_id}/result"
        )
        self.assertEqual(result.status_code, 200)
        body = result.json()["result"]
        self.assertEqual(
            body["run_final_decision_code"],
            "THREAT_MITIGATED",
        )
        self.assertEqual(
            body["rows"][0]["overall_pipeline_prediction"],
            "BENIGN",
        )
        self.assertNotIn(
            "final_decision_code",
            body["rows"][0],
        )

    def test_invalid_requests_unknown_runs_and_failures(self):
        invalid = self.client.post(
            "/api/v1/runs",
            json={
                "dataset_id": "pilot.parquet",
                "max_graph_executions": 2,
            },
        )
        self.assertEqual(invalid.status_code, 422)

        missing = self.client.get("/api/v1/runs/missing")
        self.assertEqual(missing.status_code, 404)

        self.runner.side_effect = RuntimeError("failure")
        failed = self.client.post(
            "/api/v1/runs",
            json={"dataset_id": "pilot.parquet"},
        )
        self.assertEqual(failed.status_code, 500)

    def test_interrupted_result_is_not_successful(self):
        self.runner.return_value = self.report(
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
                }
            ],
        )
        response = self.client.post(
            "/api/v1/runs",
            json={"dataset_id": "pilot.parquet"},
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["status"], "INTERRUPTED")
        self.assertIsNone(
            response.json()["run_final_decision_code"]
        )

    def test_run_records_survive_api_restart(self):
        response = self.client.post(
            "/api/v1/runs",
            json={"dataset_id": "pilot.parquet"},
        )
        self.assertEqual(response.status_code, 201)
        run_id = response.json()["run_id"]

        restarted_client = TestClient(
            create_app(
                run_service=self.service,
                run_store_path=self.run_store_path,
            )
        )
        restored = restarted_client.get(
            f"/api/v1/runs/{run_id}/result"
        )
        self.assertEqual(restored.status_code, 200)
        self.assertEqual(restored.json()["run_id"], run_id)
        self.assertEqual(
            restored.json()["result"]["run_status"],
            "COMPLETED",
        )

    def test_running_record_is_fail_closed_after_api_restart(self):
        self.run_store_path.write_text(
            json.dumps(
                {
                    "stale-run": {
                        "run_id": "stale-run",
                        "status": "RUNNING",
                        "run_status": "RUNNING",
                    }
                }
            ),
            encoding="utf-8",
        )
        restarted_client = TestClient(
            create_app(
                run_service=self.service,
                run_store_path=self.run_store_path,
            )
        )
        response = restarted_client.get("/api/v1/runs/stale-run")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "FAILED")
        self.assertIn("server stopped", response.json()["error"])


if __name__ == "__main__":
    unittest.main()
