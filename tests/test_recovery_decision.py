import unittest

from agents.monitoring_agent import monitoring_agent
from agents.verification_agent import verification_agent
from core.graph import (
    final_decision_agent,
    get_monitoring_status,
    route_after_risk,
    route_after_monitoring,
    route_after_verification,
)


def observation(packet_rate=100, packets=100, syn=0, rst=0, bytes_rate=100):
    return {
        "packet_count": packets,
        "average_flow_packets_per_second": packet_rate,
        "average_flow_bytes_per_second": bytes_rate,
        "syn_flag_count": syn,
        "rst_flag_count": rst,
        "ack_flag_count": 0,
    }


def monitoring_state(current, previous=None, **overrides):
    previous = previous or current
    state = {
        "raw_data": previous,
        "monitoring_observations": [current],
        "monitoring_count": 0,
        "severity": "LOW",
        "risk_score": 0.0,
        "recovery_count": 0,
        "severity_history": [],
        "response_pending": False,
        "max_monitoring_iterations": 5,
    }
    state.update(overrides)
    return state


class RecoveryDecisionTests(unittest.TestCase):
    def test_anomaly_routes_to_detection_before_risk_escalation(self):
        state = {
            "monitoring_result": {
                "severity_change": "INCREASED",
                "risk_increased": True,
            },
            "monitoring_detection_required": True,
            "monitoring_count": 1,
            "monitoring_observations": [{}],
            "response_pending": False,
        }
        self.assertEqual(
            route_after_monitoring(state),
            "detection_agent",
        )

    def test_stable_monitoring_does_not_escalate(self):
        result = monitoring_agent(
            monitoring_state(observation(), observation())
        )

        self.assertEqual(
            result["monitoring_result"]["severity_change"],
            "STABLE",
        )
        self.assertFalse(
            result["monitoring_result"]["risk_increased"]
        )
        self.assertEqual(
            route_after_monitoring(result),
            "monitoring_agent",
        )


    def test_increased_severity_routes_to_detection(self):
        result = monitoring_agent(
            monitoring_state(
                observation(packet_rate=2000, syn=10),
                observation(),
            )
        )
        self.assertEqual(
            result["monitoring_result"]["severity_change"],
            "INCREASED",
        )
        self.assertEqual(
            route_after_monitoring(result),
            "detection_agent",
        )

    def test_risk_assessment_remains_for_non_detection_escalation(self):
        state = monitoring_state(
            observation(),
            monitoring_result={
                "severity_change": "INCREASED",
                "risk_increased": True,
            },
            monitoring_detection_required=False,
        )
        self.assertEqual(
            route_after_monitoring(state),
            "risk_agent",
        )

    def test_increased_risk_routes_from_risk_assessment_to_response(self):
        state = monitoring_state(
            observation(),
            monitoring_result={
                "severity_change": "INCREASED",
                "risk_increased": True,
            },
            severity="MEDIUM",
            risk_score=40,
            monitoring_count=2,
        )
        self.assertEqual(
            route_after_risk(state),
            "response_agent",
        )

    def test_stable_risk_assessment_returns_to_monitoring(self):
        state = monitoring_state(
            observation(),
            monitoring_result={
                "severity_change": "STABLE",
                "risk_increased": False,
            },
            severity="MEDIUM",
            risk_score=40,
            monitoring_count=2,
        )
        self.assertEqual(
            route_after_risk(state),
            "monitoring_agent",
        )

    def test_decreased_risk_assessment_returns_to_monitoring(self):
        state = monitoring_state(
            observation(),
            monitoring_result={
                "severity_change": "DECREASED",
                "risk_increased": False,
            },
            severity="MEDIUM",
            risk_score=20,
            monitoring_count=2,
        )
        self.assertEqual(
            route_after_risk(state),
            "monitoring_agent",
        )

    def test_later_anomaly_reaches_detector_after_response_verification(self):
        state = monitoring_state(
            observation(packet_rate=2000, syn=10),
            response_pending=True,
            monitoring_count=2,
            detection_history=[
                {
                    "monitoring_cycle": 1,
                    "raw_response": "THREAT_DETECTED: YES",
                }
            ],
            monitoring_result={
                "anomaly_detected": True,
                "severity_change": "INCREASED",
                "risk_increased": True,
            },
        )
        self.assertEqual(
            route_after_monitoring(state),
            "verification_agent",
        )
        state["response_pending"] = False
        self.assertEqual(
            route_after_verification(state),
            "detection_agent",
        )

    def test_detector_runs_at_most_once_per_monitoring_cycle(self):
        state = monitoring_state(
            observation(packet_rate=2000, syn=10),
            monitoring_count=2,
            monitoring_detection_required=True,
            detection_history=[
                {
                    "monitoring_cycle": 2,
                    "raw_response": "THREAT_DETECTED: NO",
                }
            ],
            monitoring_result={
                "anomaly_detected": True,
                "severity_change": "STABLE",
                "risk_increased": False,
            },
        )
        self.assertEqual(
            route_after_monitoring(state),
            "monitoring_agent",
        )


    def test_ineffective_response_is_verified_from_subsequent_monitoring(
        self
    ):
        state = monitoring_state(
            observation(packet_rate=2000, syn=10),
            observation(),
            severity="HIGH",
            risk_score=70,
            response_pending=True,
            response_result={"raw_response": "blocked host"},
            response_cycle=1,
            severity_history=[
                {
                    "stage": "monitoring",
                    "cycle": 0,
                    "anomaly_score": 40,
                }
            ],
            detection_history=[
                {
                    "monitoring_cycle": 1,
                    "raw_response": "THREAT_DETECTED: YES",
                }
            ],
        )
        monitored = monitoring_agent(state)
        self.assertEqual(
            route_after_monitoring(
                {
                    **state,
                    **monitored,
                    "response_pending": True,
                }
            ),
            "verification_agent",
        )

        verified = verification_agent(
            {
                **state,
                **monitored,
                "response_pending": True,
            }
        )
        self.assertEqual(
            verified["verification_result"]["verification_status"],
            "RESPONSE_INEFFECTIVE",
        )
        self.assertEqual(
            route_after_verification(
                {
                    **state,
                    **monitored,
                    **verified,
                }
            ),
            "risk_agent",
        )


    def test_decreasing_risk_does_not_establish_containment(self):
        result = monitoring_agent(
            monitoring_state(
                observation(),
                observation(packet_rate=2000, syn=10),
                severity="MEDIUM",
                risk_score=60,
            )
        )

        self.assertEqual(
            result["monitoring_result"]["severity_change"],
            "DECREASED",
        )
        self.assertLess(result["risk_score"], 60)
        self.assertEqual(
            route_after_monitoring(result),
            "monitoring_agent",
        )

    def test_missing_monitoring_evidence_is_indeterminate(self):
        result = monitoring_agent(
            monitoring_state({}, {})
        )

        self.assertFalse(
            result["monitoring_result"]["evidence_valid"]
        )
        self.assertEqual(
            result["monitoring_result"]["severity_change"],
            "INDETERMINATE",
        )
        self.assertEqual(
            result["severity"],
            "LOW",
        )
        self.assertEqual(
            result["risk_score"],
            0.0,
        )
        verified = verification_agent(
            {
                **monitoring_state({}, {}),
                **result,
                "response_result": {
                    "raw_response": "RESPONSE_ACTION: isolate"
                },
            }
        )
        self.assertEqual(
            verified["verification_result"]["verification_status"],
            "RESPONSE_NOT_CONFIRMED",
        )

    def test_invalid_monitoring_evidence_cannot_produce_benign_decision(self):
        result = final_decision_agent(
            {
                "monitoring_mode": "OFFLINE_DATASET",
                "monitoring_observations": [{}, {}],
                "monitoring_count": 2,
                "severity": "LOW",
                "risk_score": 0.0,
                "monitoring_evidence_invalid": True,
            }
        )

        self.assertEqual(
            result["final_decision_code"],
            "THREAT_STATUS_UNCERTAIN",
        )
        self.assertEqual(
            result["final_decision"]["threat_status"],
            "UNCERTAIN",
        )

    def test_pending_response_cannot_be_finalized(self):
        result = final_decision_agent(
            {
                "monitoring_mode": "OFFLINE_DATASET",
                "monitoring_observations": [{}],
                "monitoring_count": 1,
                "severity": "LOW",
                "risk_score": 0.0,
                "response_pending": True,
            }
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertIsNone(result["final_decision_code"])


    def test_monitoring_limit_terminates_after_final_allowed_window(self):
        state = {
            "monitoring_count": 5,
            "max_monitoring_iterations": 5,
            "monitoring_result": {
                "severity_change": "STABLE",
                "risk_increased": False,
            },
            "response_pending": False,
        }
        self.assertEqual(
            route_after_monitoring(state),
            "final_decision",
        )
        self.assertEqual(
            route_after_verification(state),
            "final_decision",
        )

        state["monitoring_count"] = 6
        state["monitoring_result"]["severity_change"] = "INCREASED"
        self.assertEqual(
            route_after_monitoring(state),
            "final_decision",
        )


    def test_ineffective_medium_response_is_not_marked_mitigated(self):
        result = final_decision_agent(
            {
                "severity": "MEDIUM",
                "risk_score": 60,
                "monitoring_count": 5,
                "monitoring_observations": [{}, {}, {}, {}, {}],
                "response_history": [{"response_cycle": 1}],
                "verification_result": {
                    "verification_status": "RESPONSE_INEFFECTIVE",
                },
            },
        )

        decision = result["final_decision"]
        self.assertEqual(result["status"], "completed")
        self.assertEqual(decision["threat_status"], "UNRESOLVED")
        self.assertEqual(
            decision["containment_status"],
            "NOT_ESTABLISHED",
        )
        self.assertEqual(
            decision["decision_code"],
            "THREAT_UNRESOLVED_RESPONSE_REQUIRED",
        )

    def test_effective_response_does_not_prove_medium_containment(self):
        result = final_decision_agent(
            {
                "severity": "MEDIUM",
                "risk_score": 60,
                "monitoring_count": 8,
                "monitoring_observations": [{}, {}, {}, {}, {}, {}, {}, {}],
                "monitoring_mode": "OFFLINE_DATASET",
                "response_history": [
                    {"response_cycle": 1},
                    {"response_cycle": 2},
                    {"response_cycle": 3},
                    {"response_cycle": 4},
                ],
                "verification_result": {
                    "verification_status": "RESPONSE_EFFECTIVE",
                },
            }
        )

        decision = result["final_decision"]
        self.assertEqual(
            decision["decision_code"],
            "THREAT_UNRESOLVED_RECOVERY_IN_PROGRESS",
        )
        self.assertEqual(decision["response_effectiveness"], "EFFECTIVE")
        self.assertEqual(
            decision["containment_status"],
            "NOT_ESTABLISHED",
        )
        self.assertEqual(
            decision["monitoring_status"],
            "OFFLINE_DATASET_WINDOWS_EXHAUSTED",
        )
        self.assertEqual(
            decision["response_execution"],
            "SIMULATED_RECOMMENDATION",
        )
        self.assertIn(
            "does not prove threat containment",
            decision["decision_reason"],
        )
        self.assertEqual(
            decision["recommended_next_action"],
            "CONTINUE_MONITORING_AND_RESPONSE",
        )

    def test_monitoring_status_distinguishes_offline_and_live_modes(self):
        self.assertEqual(
            get_monitoring_status(
                {
                    "monitoring_mode": "OFFLINE_DATASET",
                    "monitoring_observations": [{}, {}],
                },
                2,
            ),
            "OFFLINE_DATASET_WINDOWS_EXHAUSTED",
        )
        self.assertEqual(
            get_monitoring_status(
                {"monitoring_mode": "LIVE"},
                2,
            ),
            "LIVE_MONITORING_ACTIVE",
        )


    def test_effective_low_risk_response_can_be_marked_mitigated(self):
        result = final_decision_agent(
            {
                "severity": "LOW",
                "risk_score": 20,
                "monitoring_count": 3,
                "monitoring_observations": [{}, {}, {}],
                "response_history": [{"response_cycle": 1}],
                "verification_result": {
                    "verification_status": "RESPONSE_EFFECTIVE",
                },
            },
        )

        decision = result["final_decision"]
        self.assertEqual(decision["threat_status"], "MITIGATED")
        self.assertEqual(
            decision["containment_status"],
            "SUPPORTED_BY_MONITORING",
        )

    def test_severity_levels_have_consistent_terminal_decisions(self):
        expected = {
            "LOW": (
                "NO_ACTIVE_THREAT_CONFIRMED",
                "CONTINUE_ROUTINE_MONITORING",
                "NOT_REQUIRED",
            ),
            "MEDIUM": (
                "THREAT_UNRESOLVED_RECOVERY_IN_PROGRESS",
                "CONTINUE_MONITORING_AND_RESPONSE",
                "RESPONSE_EFFECTIVE",
            ),
            "HIGH": (
                "ACTIVE_HIGH_RISK_THREAT",
                "ESCALATE_AND_CONTINUE_RESPONSE",
                "RESPONSE_INEFFECTIVE",
            ),
            "CRITICAL": (
                "ACTIVE_CRITICAL_THREAT",
                "ESCALATE_AND_CONTINUE_RESPONSE",
                "RESPONSE_INEFFECTIVE",
            ),
        }

        for severity, (
            decision_code,
            next_action,
            verification_status,
        ) in expected.items():
            result = final_decision_agent(
                {
                    "severity": severity,
                    "risk_score": {
                        "LOW": 20,
                        "MEDIUM": 60,
                        "HIGH": 80,
                        "CRITICAL": 95,
                    }[severity],
                    "monitoring_count": 1,
                        "monitoring_observations": [{}],
                        "verification_result": {
                            "verification_status": (
                                verification_status
                            )
                        },
                }
            )
            decision = result["final_decision"]
            self.assertEqual(
                decision["decision_code"],
                decision_code,
            )
            self.assertEqual(
                decision["recommended_next_action"],
                next_action,
            )

    def test_incomplete_monitoring_has_no_terminal_decision(self):
        result = final_decision_agent(
            {
                "severity": "LOW",
                "risk_score": 20,
                "monitoring_count": 1,
                "monitoring_observations": [{}, {}],
                "response_history": [],
            }
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertIsNone(result["final_decision_code"])
        self.assertEqual(
            result["final_decision"]["threat_status"],
            "INCOMPLETE",
        )

    def test_iterative_monitoring_before_limit_has_no_terminal_decision(self):
        result = final_decision_agent(
            {
                "monitoring_mode": "LIVE",
                "monitoring_observations": [],
                "monitoring_count": 2,
                "max_monitoring_iterations": 3,
                "severity": "LOW",
                "risk_score": 10,
            }
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertIsNone(result["final_decision_code"])

    def test_iterative_monitoring_at_limit_without_observations_is_incomplete(
        self
    ):
        result = final_decision_agent(
            {
                "monitoring_mode": "LIVE",
                "monitoring_observations": [],
                "monitoring_count": 3,
                "max_monitoring_iterations": 3,
                "severity": "LOW",
                "risk_score": 10,
                "response_history": [],
            }
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertIsNone(result["final_decision_code"])

    def test_iterative_monitoring_at_limit_with_observations_can_receive_decision(
        self
    ):
        result = final_decision_agent(
            {
                "monitoring_mode": "LIVE",
                "monitoring_observations": [{}],
                "monitoring_count": 3,
                "max_monitoring_iterations": 3,
                "severity": "LOW",
                "risk_score": 10,
                "response_history": [],
                "verification_result": {
                    "verification_status": "NOT_REQUIRED"
                },
            }
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(
            result["final_decision_code"],
            "NO_ACTIVE_THREAT_CONFIRMED",
        )

    def test_missing_verification_status_fails_closed(self):
        result = final_decision_agent(
            {
                "monitoring_mode": "OFFLINE_DATASET",
                "monitoring_observations": [{}],
                "monitoring_count": 1,
                "severity": "LOW",
                "risk_score": 10,
                "response_history": [],
                "verification_result": {},
            }
        )

        self.assertEqual(
            result["final_decision_code"],
            "THREAT_STATUS_UNCERTAIN",
        )
        self.assertEqual(
            result["final_decision"]["containment_status"],
            "NOT_ESTABLISHED",
        )

    def test_unknown_verification_status_fails_closed(self):
        result = final_decision_agent(
            {
                "monitoring_mode": "OFFLINE_DATASET",
                "monitoring_observations": [{}],
                "monitoring_count": 1,
                "severity": "LOW",
                "risk_score": 10,
                "response_history": [],
                "verification_result": {
                    "verification_status": "MODEL_FAILED"
                },
            }
        )

        self.assertEqual(
            result["final_decision_code"],
            "THREAT_STATUS_UNCERTAIN",
        )
        self.assertEqual(
            result["final_decision"]["threat_status"],
            "UNCERTAIN",
        )

    def test_empty_offline_observations_do_not_establish_completion(self):
        result = final_decision_agent(
            {
                "monitoring_mode": "OFFLINE_DATASET",
                "monitoring_observations": [],
                "monitoring_count": 3,
                "max_monitoring_iterations": 3,
                "severity": "LOW",
                "risk_score": 10,
            }
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertIsNone(result["final_decision_code"])

    def test_interruption_suppresses_decision_at_monitoring_limit(self):
        result = final_decision_agent(
            {
                "monitoring_mode": "LIVE",
                "monitoring_observations": [],
                "monitoring_count": 3,
                "max_monitoring_iterations": 3,
                "interrupted": True,
                "severity": "LOW",
                "risk_score": 10,
            }
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertIsNone(result["final_decision_code"])
