import re

from services.llm_service import generate_response


SEVERITY_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


def get_higher_severity(
    first_severity,
    second_severity
):
    first_level = SEVERITY_LEVELS.get(
        first_severity,
        1
    )

    second_level = SEVERITY_LEVELS.get(
        second_severity,
        1
    )

    if first_level >= second_level:
        return first_severity

    return second_severity


def risk_agent(state):
    detection_result = state.get(
        "detection_result",
        {}
    )

    analysis_result = state.get(
        "analysis_result",
        {}
    )

    correlation_result = state.get(
        "correlation_result",
        {}
    )

    monitoring_result = state.get(
        "monitoring_result",
        {}
    )

    previous_severity = state.get(
        "severity",
        "LOW"
    )

    previous_risk_score = state.get(
        "risk_score",
        0.0
    )

    anomaly_score = monitoring_result.get(
        "anomaly_score",
        0
    )

    severity_change = monitoring_result.get(
        "severity_change",
        "STABLE"
    )

    monitoring_severity = state.get(
        "severity",
        "LOW"
    )

    prompt = f"""
You are a cybersecurity risk assessment agent.

Assess the security incident using the following evidence.

Detection:
{detection_result}

Analysis:
{analysis_result}

Correlation:
{correlation_result}

Monitoring:
{monitoring_result}

Previous severity:
{previous_severity}

Previous risk score:
{previous_risk_score}

Monitoring severity:
{monitoring_severity}

Determine:

1. Likelihood
2. Potential impact
3. Threat severity
4. Risk score

Use exactly one severity:

LOW
MEDIUM
HIGH
CRITICAL

Return:

SEVERITY: <LOW|MEDIUM|HIGH|CRITICAL>
RISK_SCORE: <0-100>
LIKELIHOOD: <description>
IMPACT: <description>
JUSTIFICATION: <short explanation>
"""

    response = generate_response(
        prompt
    )

    severity_match = re.search(
        r"SEVERITY:\s*(LOW|MEDIUM|HIGH|CRITICAL)",
        response,
        re.IGNORECASE
    )

    score_match = re.search(
        r"RISK_SCORE:\s*(\d+(?:\.\d+)?)",
        response,
        re.IGNORECASE
    )

    llm_severity = (
        severity_match.group(1).upper()
        if severity_match
        else "MEDIUM"
    )

    llm_score = (
        float(score_match.group(1))
        if score_match
        else 50.0
    )

    if anomaly_score >= 80:
        evidence_severity = "CRITICAL"
    elif anomaly_score >= 60:
        evidence_severity = "HIGH"
    elif anomaly_score >= 40:
        evidence_severity = "MEDIUM"
    else:
        evidence_severity = previous_severity

    if severity_change == "INCREASED":

        if previous_severity == "LOW":
            escalation_severity = "MEDIUM"
        elif previous_severity == "MEDIUM":
            escalation_severity = "HIGH"
        elif previous_severity == "HIGH":
            escalation_severity = "CRITICAL"
        else:
            escalation_severity = "CRITICAL"

        evidence_severity = get_higher_severity(
            evidence_severity,
            escalation_severity
        )

    elif severity_change == "DECREASED":

        if anomaly_score < 40:

            if previous_severity == "CRITICAL":
                recovery_severity = "HIGH"
            elif previous_severity == "HIGH":
                recovery_severity = "MEDIUM"
            elif previous_severity == "MEDIUM":
                recovery_severity = "LOW"
            else:
                recovery_severity = "LOW"

            evidence_severity = recovery_severity

    enforced_severity = get_higher_severity(
        monitoring_severity,
        evidence_severity
    )

    if severity_change == "DECREASED":
        enforced_severity = evidence_severity

    if enforced_severity == "CRITICAL":
        enforced_score = max(
            80.0,
            anomaly_score,
            previous_risk_score
            if severity_change != "DECREASED"
            else 0.0
        )

    elif enforced_severity == "HIGH":
        enforced_score = max(
            60.0,
            anomaly_score,
            previous_risk_score
            if severity_change != "DECREASED"
            else 0.0
        )

    elif enforced_severity == "MEDIUM":
        enforced_score = max(
            40.0,
            anomaly_score,
            previous_risk_score
            if severity_change != "DECREASED"
            else 0.0
        )

    else:
        enforced_score = min(
            39.0,
            max(
                0.0,
                anomaly_score
            )
        )

    if severity_change == "STABLE":
        if previous_severity == enforced_severity:
            enforced_score = max(
                previous_risk_score,
                enforced_score
            )

    severity_history = state.get(
        "severity_history",
        []
    )

    updated_history = (
        severity_history
        + [
            {
                "stage": "risk_assessment",
                "monitoring_cycle": state.get(
                    "monitoring_count",
                    0
                ),
                "llm_severity": llm_severity,
                "llm_risk_score": llm_score,
                "severity": enforced_severity,
                "risk_score": round(
                    enforced_score,
                    2
                ),
                "anomaly_score": anomaly_score,
                "severity_change": severity_change
            }
        ]
    )

    return {
        "risk_result": {
            "raw_response": response,
            "llm_severity": llm_severity,
            "llm_risk_score": llm_score,
            "enforced_severity": (
                enforced_severity
            ),
            "enforced_risk_score": round(
                enforced_score,
                2
            )
        },

        "severity": enforced_severity,

        "risk_score": round(
            enforced_score,
            2
        ),

        "severity_history": (
            updated_history
        ),

        "status": (
            "risk_assessment_completed"
        )
    }