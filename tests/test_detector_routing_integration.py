import unittest
from unittest.mock import patch

from core import graph as graph_module


class DetectorRoutingIntegrationTests(unittest.TestCase):
    def test_multi_cycle_response_verification_and_detector_routing(self):
        trace = []

        def mocked_monitoring_agent(state):
            cycle = state.get("monitoring_count", 0) + 1
            anomalous = cycle in (1, 2)
            trace.append(("monitoring", cycle, anomalous))
            return {
                "monitoring_result": {
                    "anomaly_detected": anomalous,
                    "severity_change": (
                        "INCREASED" if anomalous else "STABLE"
                    ),
                    "risk_increased": anomalous,
                },
                "current_observation": {
                    "cycle": cycle,
                },
                "monitoring_count": cycle,
                "monitoring_detection_required": anomalous,
                "severity": "HIGH" if anomalous else "LOW",
                "risk_score": 60.0 if anomalous else 0.0,
            }

        def mocked_detection_agent(state):
            cycle = state["monitoring_count"]
            trace.append(("detection", cycle))
            return {
                "detection_result": {
                    "raw_response": "THREAT_DETECTED: YES",
                    "monitoring_cycle": cycle,
                },
                "detection_history": state.get(
                    "detection_history",
                    [],
                )
                + [
                    {
                        "monitoring_cycle": cycle,
                        "raw_response": "THREAT_DETECTED: YES",
                    }
                ],
            }

        def mocked_analysis_agent(state):
            trace.append(("analysis", state["monitoring_count"]))
            return {}

        def mocked_correlation_agent(state):
            trace.append(("correlation", state["monitoring_count"]))
            return {}

        def mocked_risk_agent(state):
            trace.append(("risk", state["monitoring_count"]))
            return {}

        def mocked_response_agent(state):
            trace.append(("response", state["monitoring_count"]))
            return {
                "response_pending": True,
                "response_result": {
                    "raw_response": "deterministic response",
                },
            }

        def mocked_verification_agent(state):
            trace.append(("verification", state["monitoring_count"]))
            return {
                "response_pending": False,
                "verification_result": {
                    "verification_status": "RESPONSE_INEFFECTIVE",
                },
            }

        with patch.object(
            graph_module,
            "monitoring_agent",
            mocked_monitoring_agent,
        ), patch.object(
            graph_module,
            "detection_agent",
            mocked_detection_agent,
        ), patch.object(
            graph_module,
            "analysis_agent",
            mocked_analysis_agent,
        ), patch.object(
            graph_module,
            "correlation_agent",
            mocked_correlation_agent,
        ), patch.object(
            graph_module,
            "risk_agent",
            mocked_risk_agent,
        ), patch.object(
            graph_module,
            "response_agent",
            mocked_response_agent,
        ), patch.object(
            graph_module,
            "verification_agent",
            mocked_verification_agent,
        ):
            compiled = graph_module.build_graph()
            result = compiled.invoke(
                {
                    "monitoring_count": 0,
                    "monitoring_observations": [{}, {}, {}],
                    "severity": "LOW",
                    "risk_score": 0.0,
                    "response_pending": False,
                    "response_history": [],
                    "severity_history": [],
                    "detection_history": [],
                    "max_monitoring_iterations": 3,
                    "monitoring_mode": "OFFLINE_DATASET",
                }
            )

        detector_cycles = [
            cycle
            for node, cycle, *rest in trace
            if node == "detection"
        ]
        self.assertEqual(detector_cycles, [1, 2])
        self.assertEqual(len(detector_cycles), len(set(detector_cycles)))

        first_response = trace.index(("response", 1))
        first_later_monitoring = trace.index(("monitoring", 2, True))
        self.assertLess(first_response, first_later_monitoring)
        self.assertIn(
            ("verification", 2),
            trace,
        )
        self.assertLess(
            trace.index(("verification", 2)),
            trace.index(("detection", 2)),
        )
        self.assertEqual(
            result["final_decision_code"],
            "THREAT_UNRESOLVED_RESPONSE_REQUIRED",
        )
        self.assertEqual(
            result["monitoring_count"],
            3,
        )


if __name__ == "__main__":
    unittest.main()
