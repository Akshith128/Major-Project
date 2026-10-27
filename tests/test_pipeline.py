import json
import unittest

from aegis import audit, auth, config, control, data, family
from aegis.family import FamilyVote
from aegis.agents import governance_agent, monitoring_score, risk_agent
from aegis.evaluation import confusion, expected_attack_type, mcnemar, wilson
from aegis.graph import build_graph
from aegis.llm import NoLLM, parse_json, LLMUnavailable
from aegis.runs import ReviewNotAllowed, RunPaused, RunService

from .helpers import ANALYST, FakeLLM, isolate, make_dataset


class DataTests(unittest.TestCase):
    def setUp(self):
        self.dir = isolate(self)
        self.dataset = make_dataset(self.dir)

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

    def test_seed_changes_spread_windows(self):
        a = data.load_windows(self.dataset, windows=3, window_size=50, seed=1)
        b = data.load_windows(self.dataset, windows=3, window_size=50, seed=2)
        self.assertNotEqual([w["row_start"] for w in a], [w["row_start"] for w in b])

    def test_ablation_removes_tcp_window_feature(self):
        w = data.load_windows(self.dataset, windows=1, window_size=100, ablate_tcp_window=True)[0]
        self.assertNotIn("unique_tcp_window_ratio", w["features"])
        self.assertGreaterEqual(monitoring_score(w["features"]), 0)

    def test_label_threshold_controls_ground_truth(self):
        # rows 250-349 hold 50 benign + 50 attack flows
        strict = data.load_windows(self.dataset, 1, 100, "sequential", 250, label_threshold=0.6)[0]
        loose = data.load_windows(self.dataset, 1, 100, "sequential", 250, label_threshold=0.1)[0]
        self.assertFalse(strict["truth"]["is_attack"])
        self.assertTrue(loose["truth"]["is_attack"])

    def test_infiltration_days_are_flagged(self):
        make_dataset(self.dir, name="Infil1-Wednesday-28-02-2018_TrafficForML_CICFlowMeter.parquet")
        infil = next(d for d in data.list_datasets() if d["dataset_id"].startswith("Infil"))
        self.assertTrue(infil["excluded_by_default"])
        self.assertIn("unrecoverable", infil["caution"])


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

    def test_decisions_record_provenance(self):
        state = self.run_graph(FakeLLM(), self.features_attack)
        p = state["detection"]["provenance"]
        self.assertEqual(p["prompt_template"], "detection-v1")
        self.assertEqual(len(p["prompt_sha256"]), 64)
        self.assertEqual(p["model_version"], "fake-001")
        self.assertTrue(p["schema_valid"])
        self.assertEqual(state["response"]["provenance"]["tokens_in"], 100)

    def test_invalid_llm_reply_falls_back(self):
        bad = FakeLLM(detection={"threat": True, "attack_type": "Alien Invasion", "confidence": 140, "reasoning": "x"})
        state = self.run_graph(bad, self.features_attack)
        self.assertEqual(state["detection"]["source"], "rules")
        self.assertFalse(state["detection"]["provenance"]["schema_valid"])
        self.assertEqual(state["governance"]["decision"], "PENDING_REVIEW")


class HybridTests(unittest.TestCase):
    detector = {
        "method": "isolation-forest (benign-trained)", "anomalous": True, "anomaly_score": 0.7, "threshold": 0.55,
        "score": 0.8, "confidence": 99, "deviations": ["rst_share = 1 (4.0 IQR above normal 0.09)"],
        "similar_incidents": [{"family": "DoS", "day": "DoS2", "distance": 1.0}] * 3,
    }

    def run_graph(self, llm, detector):
        window = {"index": 1, "features": GraphTests.features_attack, "detector": detector}
        return build_graph(llm).invoke({"window": window, "context": {}, "trace": []})

    def test_detector_decides_memory_names_and_llm_explains(self):
        vote = {"family": "DDoS", "group": "Volumetric flood", "votes": "3/3", "agreement": 1.0,
                "neighbours": [{"family": "DDoS", "source": "known incident", "day": "DDoS2", "distance": 0.4}] * 3}
        llm = FakeLLM()
        state = self.run_graph(llm, {**self.detector, "family_vote": vote})
        d = state["detection"]
        self.assertTrue(d["threat"])
        self.assertEqual((d["source"], d["attack_type"], d["attack_group"], d["confidence"]), ("hybrid", "DDoS", "Volumetric flood", 99))
        self.assertIn("T1498 Network Denial of Service", d["attack_techniques"])
        self.assertIn("Do NOT change the family", llm.prompts[0])
        self.assertEqual(state["monitoring"]["method"], "isolation-forest (benign-trained)")

    def test_normal_window_never_reaches_the_llm(self):
        llm = FakeLLM()
        state = self.run_graph(llm, {**self.detector, "anomalous": False, "score": 0.2})
        self.assertEqual(state["trace"], ["monitoring", "governance"])
        self.assertEqual(llm.prompts, [])

    def test_llm_can_raise_but_not_lower_severity(self):
        low = {**self.detector, "confidence": 10, "score": 0.0}
        raised = self.run_graph(FakeLLM(explanation={"severity_hint": "CRITICAL", "explanation": "x"}), low)
        self.assertEqual(raised["risk"]["severity"], "CRITICAL")
        lowered = self.run_graph(FakeLLM(explanation={"severity_hint": "LOW", "explanation": "x"}), self.detector)
        self.assertEqual(lowered["risk"]["severity"], "CRITICAL")

    def test_without_llm_family_comes_from_similar_incidents(self):
        state = self.run_graph(FakeLLM(fail=True), self.detector)
        self.assertEqual((state["detection"]["source"], state["detection"]["attack_type"]), ("anomaly", "DoS"))
        self.assertEqual(state["governance"]["decision"], "PENDING_REVIEW")


class FamilyTests(unittest.TestCase):
    def setUp(self):
        isolate(self)

    def entry(self, fam, value):
        return {"features": {"a": value, "b": value * 2}, "family": fam, "day": "d", "source": "known incident"}

    def test_vote_takes_the_nearest_majority(self):
        vote = FamilyVote([self.entry("DDoS", 0.0), self.entry("DDoS", 0.1), self.entry("DoS", 0.2),
                           self.entry("Botnet", 5.0), self.entry("Botnet", 5.1)]).vote({"a": 0.05, "b": 0.1})
        self.assertEqual((vote["family"], vote["votes"], vote["group"]), ("DDoS", "2/3", "Volumetric flood"))

    def test_confirmed_incidents_join_the_memory(self):
        family.confirm({"a": 1.0, "b": 2.0}, "Brute Force", "run1", 3, "user:ana")
        self.assertEqual(family.confirmed()[0]["family"], "Brute Force")


class AuditTests(unittest.TestCase):
    def setUp(self):
        isolate(self)
        self.chain = []
        for i in range(3):
            audit.append(self.chain, "aegis:governance", "WINDOW_DECIDED", {"window": i}, run_id="r1")

    def test_intact_chain_is_signed(self):
        result = audit.verify(self.chain, "r1")
        self.assertTrue(result["valid"])
        self.assertTrue(result["signed"])
        self.assertEqual(result["checkpoint_seq"], 3)

    def test_edit_breaks_the_chain(self):
        self.chain[1]["detail"]["window"] = 99
        result = audit.verify(self.chain, "r1")
        self.assertFalse(result["valid"])
        self.assertEqual(result["broken_at"], 2)

    def test_recomputed_chain_fails_signature(self):
        self.chain[1]["detail"]["window"] = 99
        prev = self.chain[0]["hash"]
        for record in self.chain[1:]:  # attacker rewrites every hash, but has no key
            body = {k: v for k, v in record.items() if k not in ("hash", "mac")}
            body["prev_hash"] = prev
            record.update(body, hash=audit._digest(prev, body))
            prev = record["hash"]
        result = audit.verify(self.chain, "r1")
        self.assertFalse(result["valid"])
        self.assertIn("recomputed", result["reason"])

    def test_truncation_is_detected(self):
        result = audit.verify(self.chain[:2], "r1")
        self.assertFalse(result["valid"])
        self.assertIn("truncated", result["reason"])


class EvaluationTests(unittest.TestCase):
    def test_confusion_metrics(self):
        m = confusion([True, True, False, False], [True, False, True, False])
        self.assertEqual((m["tp"], m["fn"], m["fp"], m["tn"]), (1, 1, 1, 1))
        self.assertEqual(m["precision"], 0.5)
        self.assertEqual(m["f1"], 0.5)
        self.assertEqual(m["mcc"], 0.0)
        self.assertEqual(m["balanced_accuracy"], 0.5)
        self.assertEqual(m["prevalence"], 0.5)

    def test_wilson_interval_is_wide_for_small_samples(self):
        low, high = wilson(9, 10)
        self.assertLess(low, 0.6)
        self.assertGreater(high, 0.95)

    def test_attack_labels_map_to_families(self):
        cases = {"Bot": "Botnet", "DDOS attack-HOIC": "DDoS", "DoS attacks-Hulk": "DoS",
                 "SSH-Bruteforce": "Brute Force", "Brute Force -Web": "Web Attack", "SQL Injection": "Web Attack"}
        for label, family in cases.items():
            self.assertEqual(expected_attack_type(label), family)

    def test_mcnemar_counts_discordant_windows(self):
        result = mcnemar([True] * 10, [True] * 10, [False] * 10)
        self.assertEqual((result["a_only_correct"], result["b_only_correct"]), (10, 0))
        self.assertLess(result["p_value"], 0.01)


class RunServiceTests(unittest.TestCase):
    def setUp(self):
        self.dir = isolate(self)
        self.dataset = make_dataset(self.dir)

    def service(self, llm=None):
        return RunService(self.dir / "runs", llm_factory=lambda mode: llm or NoLLM())

    def test_run_evaluates_and_audits(self):
        run = self.service(FakeLLM()).start(self.dataset, windows=6, window_size=100, user=ANALYST, background=False)
        self.assertEqual(run["status"], "COMPLETED")
        self.assertEqual(run["llm"]["provider"], "gemini")
        self.assertEqual(run["evaluation"]["monitoring"]["recall"], 1.0)
        self.assertEqual(run["audit"][0]["actor"], "user:akshith")
        self.assertEqual(run["audit"][-1]["action"], "RUN_COMPLETED")
        self.assertTrue(audit.verify(run["audit"], run["id"])["valid"])
        self.assertNotIn("flows", run["windows"][0])
        self.assertIn("tcp_window_rule", run["evaluation"]["baselines"])
        self.assertFalse(run["baselines"]["random_forest"]["available"])  # only one day-file
        self.assertEqual(run["evaluation"]["operations"]["model_versions"], ["fake-001"])

    def test_random_forest_baseline_trains_on_other_day_files(self):
        make_dataset(self.dir, name="other-day.parquet", seed=11)
        run = self.service().start(self.dataset, windows=6, window_size=100, mode="rules", background=False)
        self.assertEqual(run["baselines"]["random_forest"]["trained_on"], ["other-day.parquet"])
        self.assertIn("random_forest", run["evaluation"]["baselines"])
        self.assertIn("attack_share", run["windows"][0]["baselines"]["random_forest"])
        pairs = {(c["a"], c["b"]) for c in run["evaluation"]["comparisons"]}
        self.assertIn(("pipeline", "random_forest"), pairs)

    def test_hybrid_run_uses_anomaly_detector(self):
        make_dataset(self.dir, name="other-day.parquet", seed=11)
        run = self.service(FakeLLM()).start(self.dataset, windows=6, window_size=100, mode="hybrid", background=False)
        self.assertEqual(run["status"], "COMPLETED")
        self.assertEqual(run["detector"]["baseline"], "same-network")
        self.assertEqual(run["windows"][0]["monitoring"]["method"], "isolation-forest (benign-trained)")
        self.assertIn("detector", run["windows"][0])
        self.assertIn("attack_typing", run["evaluation"])
        flagged = [w for w in run["windows"] if w.get("detection")]
        self.assertTrue(flagged)
        self.assertIn("family_vote", flagged[0]["detection"])

    def test_approved_review_teaches_the_incident_memory(self):
        make_dataset(self.dir, name="other-day.parquet", seed=11)
        service = self.service(FakeLLM())
        run = service.start(self.dataset, windows=6, window_size=100, mode="hybrid", background=False)
        pending = [w for w in run["windows"] if w["governance"]["decision"] == "PENDING_REVIEW"]
        self.assertTrue(pending)
        reviewed = service.review(run["id"], pending[0]["index"], "APPROVED", ANALYST, "Confirmed", family_name="DoS")
        self.assertEqual((reviewed["review"]["family"], reviewed["review"]["family_corrected"]), ("DoS", reviewed["detection"]["attack_type"] != "DoS"))
        memory = family.confirmed()
        self.assertEqual((len(memory), memory[0]["family"], memory[0]["confirmed_by"]), (1, "DoS", "user:akshith"))

    def test_pause_blocks_new_runs(self):
        control.set_paused(True, "user:boss", "Investigating")
        with self.assertRaises(RunPaused):
            self.service().start(self.dataset, windows=2, window_size=100, background=False)

    def test_rules_mode_and_human_review(self):
        service = self.service()
        run = service.start(self.dataset, windows=6, window_size=100, mode="rules", background=False)
        self.assertEqual(run["llm"]["provider"], "rules")
        pending = [w for w in run["windows"] if w["governance"]["decision"] == "PENDING_REVIEW"]
        self.assertTrue(pending)

        service.review(run["id"], pending[0]["index"], "APPROVED", ANALYST, "Contain it")
        self.assertEqual(run["audit"][-1]["action"], "RESPONSE_APPROVED")
        self.assertEqual(run["audit"][-1]["actor"], "user:akshith")
        self.assertEqual(run["windows"][pending[0]["index"] - 1]["review"]["username"], "akshith")
        self.assertEqual(run["summary"]["pending_review"], len(pending) - 1)
        self.assertEqual(run["evaluation"]["governance"]["reviewed"], 1)
        with self.assertRaises(ReviewNotAllowed):
            service.review(run["id"], pending[0]["index"], "REJECTED", ANALYST)

    def test_gemini_mode_requires_key(self):
        with self.assertRaises(ValueError):
            self.service().start(self.dataset, mode="gemini", background=False)

    def test_runs_reload_from_disk(self):
        run = self.service().start(self.dataset, windows=2, window_size=100, background=False)
        reloaded = self.service()
        self.assertEqual(reloaded.get(run["id"])["status"], "COMPLETED")
        self.assertEqual(reloaded.list_runs()[0]["id"], run["id"])


class AuthTests(unittest.TestCase):
    def setUp(self):
        isolate(self)

    def test_password_login_and_token(self):
        auth.add_user("akshith", "correct horse", "responder", "Akshith")
        user = auth.authenticate("Akshith", "correct horse")
        self.assertEqual(user["role"], "responder")
        self.assertNotIn("correct horse", json.dumps(auth.load_users()))
        session = auth.issue_token(user)
        self.assertEqual(auth.read_token(session["token"])["username"], "akshith")
        with self.assertRaises(auth.AuthError):
            auth.authenticate("akshith", "wrong password")
        with self.assertRaises(auth.AuthError):
            auth.read_token(session["token"][:-2] + "xx")

    def test_permissions(self):
        self.assertTrue(auth.can("manager", "control"))
        self.assertFalse(auth.can("analyst", "control"))
        self.assertFalse(auth.can("researcher", "review"))
        self.assertFalse(auth.can("responder", "run"))


if __name__ == "__main__":
    unittest.main()
