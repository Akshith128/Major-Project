import re
from services.llm_service import generate_response


def risk_agent(state):
    detection_result = state.get("detection_result", {})
    analysis_result = state.get("analysis_result", {})
    correlation_result = state.get("correlation_result", {})

    prompt = f"""
You are a cybersecurity risk assessment agent.

Assess the severity and risk of the security incident using the detection, analysis, and correlation results.

Detection result:
{detection_result}

Analysis result:
{analysis_result}

Correlation result:
{correlation_result}

Evaluate:

1. Likelihood of successful attack
2. Potential impact
3. Threat severity
4. Overall risk score

Use exactly one severity level:

LOW
MEDIUM
HIGH
CRITICAL

Calculate a risk score from 0 to 100.

Return exactly:

SEVERITY: <LOW|MEDIUM|HIGH|CRITICAL>
RISK_SCORE: <0-100>
LIKELIHOOD: <description>
IMPACT: <description>
JUSTIFICATION: <short explanation>
"""

    response = generate_response(prompt)

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

    severity = severity_match.group(1).upper() if severity_match else "MEDIUM"
    risk_score = float(score_match.group(1)) if score_match else 50.0

    previous_history = state.get("severity_history", [])

    severity_history = previous_history + [
        {
            "stage": "risk_assessment",
            "severity": severity,
            "risk_score": risk_score
        }
    ]

    return {
        "risk_result": {
            "raw_response": response
        },
        "severity": severity,
        "risk_score": risk_score,
        "severity_history": severity_history,
        "monitoring_count": 0,
        "status": "risk_assessment_completed"
    }