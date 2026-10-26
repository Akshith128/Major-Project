from langgraph.graph import (
    StateGraph,
    START,
    END
)

from core.state import SecurityState

from agents.detection_agent import detection_agent
from agents.analysis_agent import analysis_agent
from agents.correlation_agent import correlation_agent
from agents.risk_agent import risk_agent
from agents.monitoring_agent import monitoring_agent
from agents.response_agent import response_agent
from agents.verification_agent import verification_agent


DEFAULT_MAX_MONITORING_ITERATIONS = 20


def get_monitoring_limit(state):
    configured_limit = state.get(
        "max_monitoring_iterations"
    )
    if configured_limit is not None:
        return max(1, int(configured_limit))

    observations = state.get(
        "monitoring_observations",
        []
    )
    if observations:
        return len(observations)

    return DEFAULT_MAX_MONITORING_ITERATIONS


def get_monitoring_status(state, monitoring_count):
    monitoring_mode = state.get(
        "monitoring_mode",
        "OFFLINE_DATASET"
    )

    observations = state.get(
        "monitoring_observations",
        []
    )

    if (
        monitoring_mode == "OFFLINE_DATASET"
        and observations
        and monitoring_count >= len(observations)
    ):
        return "OFFLINE_DATASET_WINDOWS_EXHAUSTED"

    if monitoring_mode == "LIVE":
        return "LIVE_MONITORING_ACTIVE"

    return "MONITORING_LIMIT_REACHED"


def detector_evaluated_for_cycle(state):
    monitoring_count = state.get(
        "monitoring_count",
        0
    )
    return any(
        item.get("monitoring_cycle") == monitoring_count
        for item in state.get("detection_history", [])
    )


def route_after_monitoring(state):
    monitoring_result = state.get(
        "monitoring_result",
        {}
    )

    monitoring_count = state.get(
        "monitoring_count",
        0
    )

    monitoring_limit = get_monitoring_limit(state)

    if monitoring_count > monitoring_limit:
        return "final_decision"

    if state.get(
        "response_pending",
        False
    ):
        return "verification_agent"

    if state.get(
        "monitoring_detection_required",
        False
    ) and not detector_evaluated_for_cycle(state):
        return "detection_agent"

    risk_increased = (
        monitoring_result.get(
            "severity_change"
        ) == "INCREASED"
        or monitoring_result.get(
            "risk_increased",
            False
        )
    )

    if risk_increased:
        return "risk_agent"

    if monitoring_count >= monitoring_limit:
        return "final_decision"

    return "monitoring_agent"


def route_after_detection(state):
    detection_result = state.get(
        "detection_result",
        {}
    )

    response = detection_result.get(
        "raw_response",
        ""
    )

    if "THREAT_DETECTED: YES" in response.upper():
        return "analysis_agent"

    return "monitoring_agent"


def route_after_risk(state):
    severity = state.get(
        "severity",
        "LOW"
    )

    risk_score = state.get(
        "risk_score",
        0
    )

    monitoring_result = state.get(
        "monitoring_result",
        {}
    )

    risk_increased = (
        monitoring_result.get(
            "severity_change"
        ) == "INCREASED"
        or monitoring_result.get(
            "risk_increased",
            False
        )
    )

    if (
        risk_increased
        or
        severity in [
            "HIGH",
            "CRITICAL"
        ]
        or risk_score >= 60
    ):
        return "response_agent"

    return "monitoring_agent"


def monitoring_completed(state):
    """Return whether the run has enough evidence for a terminal decision."""
    if (
        state.get("interrupted", False)
        or state.get("run_status") == "INTERRUPTED"
        or state.get("interruption_reason")
        or state.get("response_pending", False)
    ):
        return False

    monitoring_count = state.get(
        "monitoring_count",
        0
    )
    observations = state.get(
        "monitoring_observations",
        []
    )
    monitoring_mode = state.get(
        "monitoring_mode",
        "OFFLINE_DATASET"
    )

    if monitoring_mode == "OFFLINE_DATASET":
        return bool(observations) and (
            monitoring_count >= len(observations)
        )

    configured_limit = state.get(
        "max_monitoring_iterations"
    )
    return (
        bool(observations)
        and
        configured_limit is not None
        and monitoring_count >= max(
            1,
            int(configured_limit)
        )
    )


def route_after_verification(state):
    monitoring_result = state.get(
        "monitoring_result",
        {}
    )

    if (
        state.get("monitoring_count", 0)
        <= get_monitoring_limit(state)
        and monitoring_result.get(
            "anomaly_detected",
            False,
        )
        and not detector_evaluated_for_cycle(state)
    ):
        return "detection_agent"

    if (
        state.get("monitoring_count", 0)
        <= get_monitoring_limit(state)
        and (
            monitoring_result.get("severity_change")
            == "INCREASED"
            or monitoring_result.get("risk_increased", False)
        )
    ):
        return "risk_agent"

    if state.get(
        "monitoring_count",
        0
    ) >= get_monitoring_limit(state):
        return "final_decision"

    return "monitoring_agent"


def final_decision_agent(state):
    if not monitoring_completed(state):
        reason = (
            "Monitoring did not provide completion evidence; "
            "no run-level threat decision was recorded."
        )
        return {
            "final_decision": {
                "decision_code": None,
                "threat_status": "INCOMPLETE",
                "final_severity": state.get(
                    "severity",
                    "LOW"
                ),
                "final_risk_score": state.get(
                    "risk_score",
                    0.0
                ),
                "response_outcome": state.get(
                    "verification_result",
                    {}
                ).get(
                    "verification_status",
                    "NOT_REQUIRED"
                ),
                "containment_status": "NOT_ESTABLISHED",
                "monitoring_status": "INCOMPLETE",
                "decision_reason": reason,
                "recommended_next_action": (
                    "CONTINUE_MONITORING"
                ),
                "monitoring_iterations": state.get(
                    "monitoring_count",
                    0
                )
            },
            "final_decision_code": None,
            "final_decision_reason": reason,
            "status": "incomplete"
        }

    severity = state.get(
        "severity",
        "LOW"
    )

    risk_score = state.get(
        "risk_score",
        0.0
    )

    monitoring_count = state.get(
        "monitoring_count",
        0
    )

    verification_result = state.get(
        "verification_result",
        {}
    )

    verification_status = verification_result.get(
        "verification_status",
        "NOT_REQUIRED"
    )

    verification_status_present = (
        "verification_status" in verification_result
    )
    supported_verification_statuses = {
        "NOT_REQUIRED",
        "RESPONSE_EFFECTIVE",
        "RESPONSE_INEFFECTIVE",
        "RESPONSE_NOT_CONFIRMED",
        "RESPONSE_PARTIALLY_EFFECTIVE",
    }

    monitoring_status = get_monitoring_status(
        state,
        monitoring_count
    )

    if state.get(
        "monitoring_evidence_invalid",
        False
    ):
        reason = (
            "At least one monitoring window contained missing or malformed "
            "evidence; no recovery or benign outcome was established."
        )
        final_decision = {
            "decision_code": "THREAT_STATUS_UNCERTAIN",
            "threat_status": "UNCERTAIN",
            "final_severity": severity,
            "final_risk_score": risk_score,
            "response_outcome": verification_status,
            "response_effectiveness": "NOT_VERIFIED",
            "response_execution": "SIMULATED_RECOMMENDATION",
            "containment_status": "NOT_ESTABLISHED",
            "monitoring_status": monitoring_status,
            "decision_reason": reason,
            "recommended_next_action": (
                "REVIEW_EVIDENCE_AND_CONTINUE_MONITORING"
            ),
            "monitoring_iterations": monitoring_count
        }
        return {
            "final_decision": final_decision,
            "final_decision_code": (
                final_decision["decision_code"]
            ),
            "final_decision_reason": reason,
            "status": "completed"
        }

    if (
        not verification_status_present
        or verification_status not in supported_verification_statuses
        or verification_status in {
        "RESPONSE_NOT_CONFIRMED",
        "RESPONSE_PARTIALLY_EFFECTIVE",
        }
    ):
        reason = (
            "Response verification did not establish recovery or "
            "containment."
        )
        final_decision = {
            "decision_code": "THREAT_STATUS_UNCERTAIN",
            "threat_status": "UNCERTAIN",
            "final_severity": severity,
            "final_risk_score": risk_score,
            "response_outcome": verification_status,
            "response_effectiveness": "NOT_VERIFIED",
            "response_execution": "SIMULATED_RECOMMENDATION",
            "containment_status": "NOT_ESTABLISHED",
            "monitoring_status": monitoring_status,
            "decision_reason": reason,
            "recommended_next_action": (
                "REVIEW_EVIDENCE_AND_CONTINUE_MONITORING"
            ),
            "monitoring_iterations": monitoring_count
        }
        return {
            "final_decision": final_decision,
            "final_decision_code": (
                final_decision["decision_code"]
            ),
            "final_decision_reason": reason,
            "status": "completed"
        }

    response_history = state.get("response_history", [])
    response_outcome = verification_status
    containment_status = "NOT_ESTABLISHED"

    if severity == "CRITICAL":
        decision_code = "ACTIVE_CRITICAL_THREAT"
        threat_status = "ACTIVE"
        reason = (
            "Monitoring ended while the incident remained at CRITICAL "
            "severity. The response recommendation did not establish "
            "containment."
        )
        next_action = "ESCALATE_AND_CONTINUE_RESPONSE"
    elif severity == "HIGH":
        decision_code = "ACTIVE_HIGH_RISK_THREAT"
        threat_status = "ACTIVE"
        reason = (
            "Monitoring ended while the incident remained at "
            f"{severity} severity. "
            "The response recommendation did not establish containment."
        )
        next_action = "ESCALATE_AND_CONTINUE_RESPONSE"
    elif verification_status == "RESPONSE_INEFFECTIVE":
        decision_code = "THREAT_UNRESOLVED_RESPONSE_REQUIRED"
        threat_status = "UNRESOLVED"
        reason = (
            "The latest response was ineffective and the remaining "
            f"{severity} severity and risk score {risk_score} do not "
            "support containment."
        )
        next_action = "CONTINUE_RESPONSE_AND_ESCALATE"
    elif severity == "MEDIUM":
        decision_code = "THREAT_UNRESOLVED_RECOVERY_IN_PROGRESS"
        threat_status = "UNRESOLVED"
        reason = (
            "The response verification was effective and indicators "
            "improved, but MEDIUM severity remains. Effectiveness of the "
            "simulated response recommendation does not prove threat "
            "containment."
        )
        next_action = "CONTINUE_MONITORING_AND_RESPONSE"
    elif (
        severity == "LOW"
        and risk_score < 40
        and verification_status == "RESPONSE_EFFECTIVE"
    ):
        decision_code = "THREAT_MITIGATED"
        threat_status = "MITIGATED"
        containment_status = "SUPPORTED_BY_MONITORING"
        reason = (
            "Post-response monitoring shows LOW severity, risk below 40, "
            "and an effective response recommendation; containment is "
            "supported by the available monitoring evidence."
        )
        next_action = "CLOSE_WITH_CONTINUED_MONITORING"
    elif severity == "LOW" and risk_score < 40 and not response_history:
        decision_code = "NO_ACTIVE_THREAT_CONFIRMED"
        threat_status = "NO_ACTIVE_THREAT_CONFIRMED"
        containment_status = "NOT_REQUIRED"
        reason = (
            "Monitoring completed at LOW severity with risk below 40 and "
            "no response was required."
        )
        next_action = "CONTINUE_ROUTINE_MONITORING"
    else:
        decision_code = "THREAT_STATUS_UNCERTAIN"
        threat_status = "UNCERTAIN"
        reason = (
            "Available evidence is insufficient to establish containment "
            "or mitigation."
        )
        next_action = "REVIEW_EVIDENCE_AND_CONTINUE_MONITORING"

    final_decision = {
        "decision_code": decision_code,
        "threat_status": threat_status,
        "final_severity": severity,
        "final_risk_score": risk_score,
        "response_outcome": response_outcome,
        "response_effectiveness": (
            "EFFECTIVE"
            if verification_status == "RESPONSE_EFFECTIVE"
            else "INEFFECTIVE"
            if verification_status == "RESPONSE_INEFFECTIVE"
            else "NOT_VERIFIED"
        ),
        "response_execution": "SIMULATED_RECOMMENDATION",
        "containment_status": containment_status,
        "monitoring_status": monitoring_status,
        "decision_reason": reason,
        "recommended_next_action": next_action,
        "monitoring_iterations": monitoring_count
    }

    return {
        "final_decision": final_decision,
        "final_decision_code": decision_code,
        "final_decision_reason": reason,
        "status": "completed"
    }


def build_graph():

    graph = StateGraph(
        SecurityState
    )

    graph.add_node(
        "monitoring_agent",
        monitoring_agent
    )

    graph.add_node(
        "detection_agent",
        detection_agent
    )

    graph.add_node(
        "analysis_agent",
        analysis_agent
    )

    graph.add_node(
        "correlation_agent",
        correlation_agent
    )

    graph.add_node(
        "risk_agent",
        risk_agent
    )

    graph.add_node(
        "response_agent",
        response_agent
    )

    graph.add_node(
        "verification_agent",
        verification_agent
    )

    graph.add_node(
        "final_decision",
        final_decision_agent
    )

    graph.add_edge(
        START,
        "monitoring_agent"
    )

    graph.add_conditional_edges(
        "monitoring_agent",
        route_after_monitoring,
        {
            "verification_agent": (
                "verification_agent"
            ),
            "risk_agent": "risk_agent",
            "detection_agent": (
                "detection_agent"
            ),
            "monitoring_agent": (
                "monitoring_agent"
            ),
            "final_decision": (
                "final_decision"
            )
        }
    )

    graph.add_conditional_edges(
        "detection_agent",
        route_after_detection,
        {
            "analysis_agent": (
                "analysis_agent"
            ),
            "monitoring_agent": (
                "monitoring_agent"
            )
        }
    )

    graph.add_edge(
        "analysis_agent",
        "correlation_agent"
    )

    graph.add_edge(
        "correlation_agent",
        "risk_agent"
    )

    graph.add_conditional_edges(
        "risk_agent",
        route_after_risk,
        {
            "response_agent": (
                "response_agent"
            ),
            "monitoring_agent": (
                "monitoring_agent"
            )
        }
    )

    graph.add_edge(
        "response_agent",
        "monitoring_agent"
    )

    graph.add_conditional_edges(
        "verification_agent",
        route_after_verification,
        {
            "monitoring_agent": (
                "monitoring_agent"
            ),
            "detection_agent": (
                "detection_agent"
            ),
            "risk_agent": "risk_agent",
            "final_decision": (
                "final_decision"
            )
        }
    )

    graph.add_edge(
        "final_decision",
        END
    )

    return graph.compile()