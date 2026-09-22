from typing import TypedDict, List, Dict, Any, Optional


class SecurityState(TypedDict, total=False):
    event_id: str
    timestamp: str

    raw_data: Dict[str, Any]
    features: Dict[str, Any]

    detection_result: Dict[str, Any]
    analysis_result: Dict[str, Any]
    correlation_result: Dict[str, Any]
    risk_result: Dict[str, Any]

    threat_type: Optional[str]
    severity: Optional[str]
    risk_score: Optional[float]

    vulnerabilities: List[Dict[str, Any]]

    monitoring_result: Dict[str, Any]
    monitoring_count: int
    monitoring_observations: List[Dict[str, Any]]
    current_observation: Dict[str, Any]

    response_required: bool
    response_result: Dict[str, Any]

    verification_result: Dict[str, Any]

    severity_history: List[Dict[str, Any]]
    agent_messages: List[Dict[str, Any]]

    status: str
    final_decision: str