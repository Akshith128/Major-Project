import re
from services.llm_service import generate_response


def verification_agent(state):
    response_result = state.get("response_result", {})
    severity = state.get("severity", "HIGH")
    risk_score = state.get("risk_score", 0)
    raw_data = state.get("raw_data", {})

    prompt = f"""
You are a cybersecurity response verification agent.

Verify whether the defensive response has addressed the security incident.

Security event:
{raw_data}

Current severity:
{severity}

Current risk score:
{risk_score}

Response performed:
{response_result}

Determine whether the response appears effective.

Return exactly:

RESPONSE_EFFECTIVE: YES or NO
POST_RESPONSE_SEVERITY: <LOW|MEDIUM|HIGH|CRITICAL>
POST_RESPONSE_RISK_SCORE: <0-100>
VERIFICATION_REASON: <short explanation>
"""

    response = generate_response(prompt)

    effective_match = re.search(
        r"RESPONSE_EFFECTIVE:\s*(YES|NO)",
        response,
        re.IGNORECASE
    )

    severity_match = re.search(
        r"POST_RESPONSE_SEVERITY:\s*(LOW|MEDIUM|HIGH|CRITICAL)",
        response,
        re.IGNORECASE
    )

    score_match = re.search(
        r"POST_RESPONSE_RISK_SCORE:\s*(\d+(?:\.\d+)?)",
        response,
        re.IGNORECASE
    )

    effective = (
        effective_match.group(1).upper() == "YES"
        if effective_match
        else False
    )

    post_severity = (
        severity_match.group(1).upper()
        if severity_match
        else severity
    )

    post_risk_score = (
        float(score_match.group(1))
        if score_match
        else risk_score
    )

    history = state.get("severity_history", [])

    history = history + [
        {
            "stage": "verification",
            "severity": post_severity,
            "risk_score": post_risk_score,
            "response_effective": effective
        }
    ]

    return {
        "verification_result": {
            "raw_response": response,
            "response_effective": effective
        },
        "severity": post_severity,
        "risk_score": post_risk_score,
        "severity_history": history,
        "response_required": False,
        "status": "verification_completed"
    }