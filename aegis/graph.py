"""LangGraph workflow for one traffic window.

    monitoring ──suspicious──▶ detection ──threat──▶ risk ─▶ response ─┐
        │                          │                                   ▼
        └──────── clean ───────────┴────────── no threat ─────────▶ governance ─▶ END
"""

import operator
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph

from .agents import (
    governance_agent,
    make_detection_agent,
    make_response_agent,
    monitoring_agent,
    risk_agent,
)


class WindowState(TypedDict, total=False):
    window: dict  # index, row range and label-free features
    context: dict  # facts from earlier windows in the run
    monitoring: dict
    detection: dict
    risk: dict
    response: dict
    governance: dict
    trace: Annotated[list[str], operator.add]


def after_monitoring(state: WindowState) -> str:
    return "detection" if state["monitoring"]["suspicious"] else "governance"


def after_detection(state: WindowState) -> str:
    return "risk" if state["detection"]["threat"] else "governance"


def build_graph(llm):
    graph = StateGraph(WindowState)
    graph.add_node("monitoring", monitoring_agent)
    graph.add_node("detection", make_detection_agent(llm))
    graph.add_node("risk", risk_agent)
    graph.add_node("response", make_response_agent(llm))
    graph.add_node("governance", governance_agent)

    graph.add_edge(START, "monitoring")
    graph.add_conditional_edges("monitoring", after_monitoring, ["detection", "governance"])
    graph.add_conditional_edges("detection", after_detection, ["risk", "governance"])
    graph.add_edge("risk", "response")
    graph.add_edge("response", "governance")
    graph.add_edge("governance", END)
    return graph.compile()
