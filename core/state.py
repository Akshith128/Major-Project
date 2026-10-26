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
    recovery_count: int
    monitoring_evidence_invalid: bool

    ground_truth: Optional[str]
    ground_truth_sequence: List[str]

    monitoring_detection_required: bool

    response_required: bool
    response_result: Dict[str, Any]
    response_history: List[Dict[str, Any]]
    response_pending: bool

    verification_result: Dict[str, Any]

    severity_history: List[Dict[str, Any]]
    detection_history: List[Dict[str, Any]]
    agent_messages: List[Dict[str, Any]]

    response_cycle: int
    response_completed: bool

    final_decision: Dict[str, Any]
    final_decision_code: Optional[str]
    final_decision_reason: Optional[str]
    run_status: Optional[str]
    interruption_reason: Optional[str]
    interrupted: bool
    max_monitoring_iterations: int
    monitoring_mode: str

    status: str