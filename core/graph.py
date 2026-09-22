from langgraph.graph import StateGraph, START, END
from core.state import SecurityState
from agents.detection_agent import detection_agent
from agents.analysis_agent import analysis_agent
from agents.correlation_agent import correlation_agent
from agents.risk_agent import risk_agent
from agents.monitoring_agent import monitoring_agent
from agents.response_agent import response_agent
from agents.verification_agent import verification_agent


def route_after_monitoring(state):
    if state.get("response_required", False):
        return "response_agent"

    if state.get("monitoring_count", 0) >= len(
        state.get("monitoring_observations", [])
    ):
        return "end"

    return "monitoring_agent"


def build_graph():
    graph = StateGraph(SecurityState)

    graph.add_node("detection_agent", detection_agent)
    graph.add_node("analysis_agent", analysis_agent)
    graph.add_node("correlation_agent", correlation_agent)
    graph.add_node("risk_agent", risk_agent)
    graph.add_node("monitoring_agent", monitoring_agent)
    graph.add_node("response_agent", response_agent)
    graph.add_node("verification_agent", verification_agent)

    graph.add_edge(START, "detection_agent")
    graph.add_edge("detection_agent", "analysis_agent")
    graph.add_edge("analysis_agent", "correlation_agent")
    graph.add_edge("correlation_agent", "risk_agent")
    graph.add_edge("risk_agent", "monitoring_agent")

    graph.add_conditional_edges(
        "monitoring_agent",
        route_after_monitoring,
        {
            "response_agent": "response_agent",
            "monitoring_agent": "monitoring_agent",
            "end": END
        }
    )

    graph.add_edge("response_agent", "verification_agent")
    graph.add_edge("verification_agent", "monitoring_agent")

    return graph.compile()