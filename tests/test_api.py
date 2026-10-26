import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from aegis import config, data
from aegis.api import create_app
from aegis.llm import NoLLM
from aegis.runs import RunService

from .helpers import make_dataset, temp_dir


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.dir = temp_dir()
        self.dataset = make_dataset(self.dir)
        patcher = mock.patch.object(config, "DATA_DIR", self.dir)
        patcher.start()
        self.addCleanup(patcher.stop)
        data._frame.cache_clear()
        service = RunService(self.dir / "runs", llm_factory=lambda mode: NoLLM())
        self.client = TestClient(create_app(service))

    def wait_for(self, run_id):
        for _ in range(100):
            run = self.client.get(f"/api/runs/{run_id}").json()
            if run["status"] != "RUNNING":
                return run
            time.sleep(0.05)
        self.fail("run did not finish")

    def test_health_and_datasets(self):
        self.assertEqual(self.client.get("/api/health").json()["status"], "ok")
        self.assertEqual(self.client.get("/api/datasets").json()[0]["dataset_id"], self.dataset)

    def test_run_review_and_verify(self):
        started = self.client.post(
            "/api/runs", json={"dataset_id": self.dataset, "windows": 6, "window_size": 100, "operator": "Akshith"}
        )
        self.assertEqual(started.status_code, 202)
        run = self.wait_for(started.json()["id"])
        self.assertEqual(run["status"], "COMPLETED")
        self.assertEqual(self.client.get("/api/runs").json()[0]["id"], run["id"])

        pending = next(w for w in run["windows"] if w["governance"]["decision"] == "PENDING_REVIEW")
        url = f"/api/runs/{run['id']}/windows/{pending['index']}/review"
        reviewed = self.client.post(url, json={"decision": "REJECTED", "operator": "Akshith"})
        self.assertEqual(reviewed.json()["review"]["decision"], "REJECTED")
        self.assertEqual(self.client.post(url, json={"decision": "APPROVED"}).status_code, 409)
        self.assertTrue(self.client.get(f"/api/runs/{run['id']}/audit/verify").json()["valid"])

    def test_bad_requests(self):
        self.assertEqual(self.client.post("/api/runs", json={"dataset_id": "missing.parquet"}).status_code, 404)
        self.assertEqual(self.client.post("/api/runs", json={"dataset_id": self.dataset, "windows": 0}).status_code, 422)
        self.assertEqual(self.client.get("/api/runs/nope").status_code, 404)


if __name__ == "__main__":
    unittest.main()
