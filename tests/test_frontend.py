import unittest
from unittest.mock import Mock

import requests

from frontend.streamlit_app import (
    BackendClient,
    BackendError,
    _show_run_report,
)


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.ok = status_code < 400

    def json(self):
        return self._payload


class FrontendApiClientTests(unittest.TestCase):
    def setUp(self):
        self.request = Mock()
        self.client = BackendClient(
            "http://127.0.0.1:8000/",
            request=self.request,
        )

    def test_calls_existing_endpoints_and_preserves_run_contract(self):
        self.request.side_effect = [
            FakeResponse({"status": "ok"}),
            FakeResponse(
                {
                    "datasets": [
                        {
                            "dataset_id": "pilot.parquet",
                            "format": "parquet",
                            "row_count": 800,
                            "has_labels": True,
                        }
                    ]
                }
            ),
            FakeResponse(
                {
                    "dataset_id": "pilot.parquet",
                    "format": "parquet",
                    "row_count": 800,
                    "columns": [
                        {"name": "Label", "dtype": "object"}
                    ],
                    "has_labels": True,
                }
            ),
            FakeResponse(
                {
                    "run_id": "run-1",
                    "status": "COMPLETED",
                    "run_status": "COMPLETED",
                    "run_final_decision_code": "THREAT_MITIGATED",
                },
                status_code=201,
            ),
            FakeResponse(
                {
                    "run_id": "run-1",
                    "status": "COMPLETED",
                    "result": {
                        "run_final_decision_code": "THREAT_MITIGATED",
                        "rows": [
                            {
                                "window": 1,
                                "overall_pipeline_prediction": "BENIGN",
                            }
                        ],
                    },
                }
            ),
        ]

        self.assertEqual(self.client.health()["status"], "ok")
        self.assertEqual(
            self.client.datasets()["datasets"][0]["dataset_id"],
            "pilot.parquet",
        )
        self.assertEqual(
            self.client.dataset_schema("pilot.parquet")["row_count"],
            800,
        )
        run = self.client.create_run("pilot.parquet", 0, 800, 100)
        result = self.client.run_result("run-1")

        self.assertEqual(
            run["run_final_decision_code"],
            result["result"]["run_final_decision_code"],
        )
        self.assertEqual(
            result["result"]["rows"][0]["overall_pipeline_prediction"],
            "BENIGN",
        )
        create_call = self.request.call_args_list[3]
        self.assertEqual(create_call.args[:2], ("POST", "http://127.0.0.1:8000/api/v1/runs"))
        self.assertEqual(
            create_call.kwargs["json"],
            {
                "dataset_id": "pilot.parquet",
                "start_row": 0,
                "end_row": 800,
                "batch_size": 100,
                "max_graph_executions": 1,
            },
        )

    def test_http_and_transport_errors_are_clear(self):
        self.request.return_value = FakeResponse(
            {"detail": "Another run is already executing."},
            status_code=409,
        )
        with self.assertRaisesRegex(
            BackendError,
            "Another run is already executing",
        ):
            self.client.create_run("pilot.parquet", 0, 800, 100)

        self.request.side_effect = requests.ConnectionError("refused")
        with self.assertRaisesRegex(
            BackendError,
            "Backend is unavailable",
        ):
            self.client.health()

    def test_dataset_identifier_is_url_encoded(self):
        self.request.return_value = FakeResponse(
            {"dataset_id": "dataset name.parquet"}
        )
        self.client.dataset_schema("dataset name.parquet")
        self.assertIn(
            "/api/v1/datasets/dataset%20name.parquet/schema",
            self.request.call_args.args[1],
        )

    def test_report_presentation_marks_outcome_as_unconfirmed(self):
        import frontend.streamlit_app as frontend

        frontend.st = Mock()
        _show_run_report(
            {
                "run_id": "run-1",
                "status": "COMPLETED",
            },
            {
                "result": {
                    "run_status": "COMPLETED",
                    "run_final_decision_code": "THREAT_MITIGATED",
                    "rows": [],
                }
            },
        )

        warning_messages = [
            call.args[0]
            for call in frontend.st.warning.call_args_list
        ]
        self.assertTrue(
            any(
                "not a confirmed security-response action" in message
                for message in warning_messages
            )
        )

    def test_report_presentation_marks_missing_decision_as_not_successful(self):
        import frontend.streamlit_app as frontend

        frontend.st = Mock()
        _show_run_report(
            {
                "run_id": "run-1",
                "status": "INTERRUPTED",
                "interruption_reason": "quota",
            },
            {
                "result": {
                    "run_status": "INTERRUPTED",
                    "run_final_decision_code": None,
                    "rows": [],
                }
            },
        )

        info_messages = [
            call.args[0]
            for call in frontend.st.info.call_args_list
        ]
        self.assertTrue(
            any(
                "not represented as successfully mitigated" in message
                for message in info_messages
            )
        )


if __name__ == "__main__":
    unittest.main()
