import unittest
from unittest import mock

from aegis import audit, config, data
from aegis.agents import governance_agent, monitoring_score, risk_agent
from aegis.evaluation import confusion
from aegis.graph import build_graph
from aegis.llm import NoLLM, parse_json, LLMUnavailable
from aegis.runs import ReviewNotAllowed, RunService

from .helpers import FakeLLM, make_dataset, temp_dir


class DataTests(unittest.TestCase):
    def setUp(self):
        self.dir = temp_dir()
        self.dataset = make_dataset(self.dir)
        patcher = mock.patch.object(config, "DATA_DIR", self.dir)
        patcher.start()
        self.addCleanup(patcher.stop)
        data._frame.cache_clear()

    def test_windows_keep_labels_out_of_features(self):
        windows = data.load_windows(self.dataset, windows=6, window_size=100)
        self.assertEqual(len(windows), 6)
        for w in windows:
            self.assertNotIn("label", " ".join(w["features"]).lower())
        self.assertFalse(windows[0]["truth"]["is_attack"])
        self.assertTrue(windows[-1]["truth"]["is_attack"])

    def test_attack_windows_score_higher(self):
        windows = data.load_windows(self.dataset, windows=6, window_size=100)
        self.assertLess(monitoring_score(windows[0]["features"]), config.MONITORING_THRESHOLD)
        self.assertGreater(monitoring_score(windows[-1]["features"]), config.RULES_DETECTION_THRESHOLD)

    def test_rejects_paths_outside_data_dir(self):
        with self.assertRaises(ValueError):
            data.load_windows("../secrets.parquet")

    def test_sequential_range_must_fit(self):
        with self.assertRaises(ValueError):
            data.load_windows(self.dataset, windows=10, window_size=100, sampling="sequential")


class AgentTests(unittest.TestCase):
    def state(self, suspicious=True, threat=True, confidence=92, source="gemini", severity_score=0.9):
        return {
            "window": {"features": {}},
            "monitoring": {"score": severity_score, "suspicious": suspicious, "signals": []},
            "detection": {"threat": threat, "attack_type": "DDoS", "confidence": confidence, "source": source},
            "context": {"prior_incidents": {}},
        }

    def test_risk_escalates_for_repeated_incidents(self):
        first = risk_agent(self.state())["risk"]["score"]
        repeat_state = self.state()
        repeat_state["context"]["prior_incidents"] = {"DDoS": 2}
        self.assertGreater(risk_agent(repeat_state)["risk"]["score"], first)

    def test_governance_requires_review_for_high_severity(self):
        state = self.state()
        state["risk"] = {"severity": "CRITICAL"}
        self.assertEqual(governance_agent(state)["governance"]["decision"], "PENDING_REVIEW")

    def test_governance_auto_approves_low_impact_confident_response(self):
        state = self.state()
        state["risk"] = {"severity": "MEDIUM"}
        self.assertEqual(governance_agent(state)["governance"]["decision"], "AUTO_APPROVED")

    def test_governance_reviews_rule_fallback(self):
        state = self.state(source="rules")
        state["risk"] = {"severity": "LOW"}
        self.assertEqual(governance_agent(state)["governance"]["decision"], "PENDING_REVIEW")

    def test_parse_json_rejects_garbage(self):
        self.assertEqual(parse_json('```json\n{"threat": false}\n```'), {"threat": False})
        with self.assertRaises(LLMUnavailable):
            parse_json("not json")


class GraphTests(unittest.TestCase):
    features_attack = {
        "flows": 100, "tcp_share": 1.0, "udp_share": 0.0, "dominant_signature_share": 0.95,
        "unique_tcp_window_ratio": 0.01, "no_response_share": 0.9, "syn_share": 0.0,
        "rst_share": 0.9, "fin_share": 0.0, "psh_share": 0.0, "mean_packets_per_flow": 2,
        "mean_packets_per_sec": 10, "mean_bytes_per_sec": 10, "mean_flow_duration_ms": 1,
        "mean_packet_size": 0,
    }

    def run_graph(self, llm, features):
        return build_graph(llm).invoke({"window": {"index": 1, "features": features}, "context": {}, "trace": []})

    def test_clean_window_skips_detection(self):
        clean = {**self.features_attack, "tcp_share": 0.5, "dominant_signature_share": 0.05, "unique_tcp_window_ratio": 0.6}
        llm = FakeLLM()
        state = self.run_graph(llm, clean)
        self.assertEqual(state["trace"], ["monitoring", "governance"])
        self.assertEqual(llm.prompts, [])

    def test_threat_runs_full_pipeline(self):
        state = self.run_graph(FakeLLM(), self.features_attack)
        self.assertEqual(state["trace"], ["monitoring", "detection", "risk", "response", "governance"])
        self.assertEqual(state["response"]["source"], "gemini")
        self.assertEqual(state["response"]["execution"], "RECOMMENDED_NOT_EXECUTED")

    def test_detector_saying_no_threat_stops_pipeline(self):
        llm = FakeLLM(detection={"threat": False, "attack_type": None, "confidence": 70, "reasoning": "ok"})
        state = self.run_graph(llm, self.features_attack)
        self.assertEqual(state["trace"], ["monitoring", "detection", "governance"])
        self.assertEqual(state["governance"]["decision"], "NO_ACTION")

    def test_llm_failure_falls_back_to_rules(self):
        state = self.run_graph(FakeLLM(fail=True), self.features_attack)
        self.assertEqual(state["detection"]["source"], "rules")
        self.assertEqual(state["response"]["source"], "playbook")
        self.assertEqual(state["governance"]["decision"], "PENDING_REVIEW")


class AuditAndEvaluationTests(unittest.TestCase):
    def test_tampering_breaks_the_chain(self):
        chain = []
        for i in range(3):
            audit.append(chain, "aegis:governance", "WINDOW_DECIDED", {"window": i})
        self.assertTrue(audit.verify(chain)["valid"])
        chain[1]["detail"]["window"] = 99
        self.assertEqual(audit.verify(chain), {"valid": False, "records": 3, "broken_at": 2})

    def test_confusion_metrics(self):
        m = confusion([True, True, False, False], [True, False, True, False])
        self.assertEqual((m["tp"], m["fn"], m["fp"], m["tn"]), (1, 1, 1, 1))
        self.assertEqual(m["precision"], 0.5)
        self.assertEqual(m["f1"], 0.5)


class RunServiceTests(unittest.TestCase):
    def setUp(self):
        self.dir = temp_dir()
        self.dataset = make_dataset(self.dir)
        patcher = mock.patch.object(config, "DATA_DIR", self.dir)
        patcher.start()
        self.addCleanup(patcher.stop)
        data._frame.cache_clear()

    def service(self, llm=None):
        return RunService(self.dir / "runs", llm_factory=lambda mode: llm or NoLLM())

    def test_run_evaluates_and_audits(self):
        run = self.service(FakeLLM()).start(self.dataset, windows=6, window_size=100, operator="Akshith", background=False)
        self.assertEqual(run["status"], "COMPLETED")
        self.assertEqual(run["llm"]["provider"], "gemini")
        self.assertEqual(run["evaluation"]["monitoring"]["recall"], 1.0)
        self.assertEqual(run["audit"][0]["actor"], "analyst:Akshith")
        self.assertEqual(run["audit"][-1]["action"], "RUN_COMPLETED")
        self.assertTrue(audit.verify(run["audit"])["valid"])

    def test_rules_mode_and_human_review(self):
        service = self.service()
        run = service.start(self.dataset, windows=6, window_size=100, mode="rules", background=False)
        self.assertEqual(run["llm"]["provider"], "rules")
        pending = [w for w in run["windows"] if w["governance"]["decision"] == "PENDING_REVIEW"]
        self.assertTrue(pending)

        service.review(run["id"], pending[0]["index"], "APPROVED", "Akshith", "Contain it")
        self.assertEqual(run["audit"][-1]["action"], "RESPONSE_APPROVED")
        self.assertEqual(run["summary"]["pending_review"], len(pending) - 1)
        with self.assertRaises(ReviewNotAllowed):
            service.review(run["id"], pending[0]["index"], "REJECTED", "Akshith")

    def test_gemini_mode_requires_key(self):
        with self.assertRaises(ValueError):
            self.service().start(self.dataset, mode="gemini", background=False)

    def test_runs_reload_from_disk(self):
        run = self.service().start(self.dataset, windows=2, window_size=100, background=False)
        reloaded = self.service()
        self.assertEqual(reloaded.get(run["id"])["status"], "COMPLETED")
        self.assertEqual(reloaded.list_runs()[0]["id"], run["id"])


if __name__ == "__main__":
    unittest.main()
