import time
import unittest

from fastapi.testclient import TestClient

from aegis import auth
from aegis.api import create_app
from aegis.llm import NoLLM
from aegis.runs import RunService

from .helpers import isolate, make_dataset

PASSWORD = "correct horse"


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.dir = isolate(self)
        self.dataset = make_dataset(self.dir)
        for username, role in (("ana", "analyst"), ("rex", "researcher"), ("max", "manager")):
            auth.add_user(username, PASSWORD, role, username.title())
        service = RunService(self.dir / "runs", llm_factory=lambda mode: NoLLM())
        self.client = TestClient(create_app(service))

    def headers(self, username="ana"):
        token = self.client.post("/api/auth/login", json={"username": username, "password": PASSWORD}).json()["token"]
        return {"Authorization": f"Bearer {token}"}

    def wait_for(self, run_id, headers):
        for _ in range(300):  # first run pays for importing scipy/sklearn
            run = self.client.get(f"/api/runs/{run_id}", headers=headers).json()
            if run["status"] != "RUNNING":
                return run
            time.sleep(0.1)
        self.fail("run did not finish")

    def test_health_is_public_but_data_needs_sign_in(self):
        self.assertEqual(self.client.get("/api/health").json()["status"], "ok")
        self.assertEqual(self.client.get("/api/datasets").status_code, 401)
        self.assertEqual(self.client.get("/api/datasets", headers=self.headers()).json()[0]["dataset_id"], self.dataset)

    def test_wrong_password_is_rejected(self):
        response = self.client.post("/api/auth/login", json={"username": "ana", "password": "nope"})
        self.assertEqual(response.status_code, 401)

    def test_run_review_and_verify(self):
        h = self.headers()
        started = self.client.post("/api/runs", headers=h, json={"dataset_id": self.dataset, "windows": 6, "window_size": 100})
        self.assertEqual(started.status_code, 202)
        run = self.wait_for(started.json()["id"], h)
        self.assertEqual(run["status"], "COMPLETED")
        self.assertEqual(run["operator"], "Ana")
        self.assertEqual(self.client.get("/api/runs", headers=h).json()[0]["id"], run["id"])

        pending = next(w for w in run["windows"] if w["governance"]["decision"] == "PENDING_REVIEW")
        url = f"/api/runs/{run['id']}/windows/{pending['index']}/review"
        self.assertEqual(self.client.post(url, headers=self.headers("rex"), json={"decision": "APPROVED"}).status_code, 403)
        reviewed = self.client.post(url, headers=h, json={"decision": "REJECTED", "note": "False alarm"})
        self.assertEqual(reviewed.json()["review"]["username"], "ana")
        self.assertEqual(self.client.post(url, headers=h, json={"decision": "APPROVED"}).status_code, 409)
        verified = self.client.get(f"/api/runs/{run['id']}/audit/verify", headers=h).json()
        self.assertTrue(verified["valid"])
        self.assertTrue(verified["signed"])

    def test_roles_are_enforced_on_the_server(self):
        body = {"dataset_id": self.dataset, "windows": 2}
        self.assertEqual(self.client.post("/api/runs", headers=self.headers("rex"), json=body).status_code, 403)
        self.assertEqual(self.client.post("/api/control", headers=self.headers("ana"), json={"paused": True}).status_code, 403)

    def test_pause_control(self):
        m = self.headers("max")
        self.assertTrue(self.client.post("/api/control", headers=m, json={"paused": True, "reason": "drill"}).json()["paused"])
        blocked = self.client.post("/api/runs", headers=self.headers(), json={"dataset_id": self.dataset, "windows": 2})
        self.assertEqual(blocked.status_code, 409)
        self.client.post("/api/control", headers=m, json={"paused": False})
        self.assertFalse(self.client.get("/api/control", headers=m).json()["paused"])

    def test_bad_requests(self):
        h = self.headers()
        self.assertEqual(self.client.post("/api/runs", headers=h, json={"dataset_id": "missing.parquet"}).status_code, 404)
        self.assertEqual(self.client.post("/api/runs", headers=h, json={"dataset_id": self.dataset, "windows": 0}).status_code, 422)
        self.assertEqual(self.client.get("/api/runs/nope", headers=h).status_code, 404)


if __name__ == "__main__":
    unittest.main()
