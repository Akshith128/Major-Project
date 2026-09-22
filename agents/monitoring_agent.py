import re
from services.llm_service import generate_response


def monitoring_agent(state):
    raw_data = state.get("raw_data", {})
    severity = state.get("severity", "MEDIUM")
    risk_score = state.get("risk_score", 50.0)
    severity_history = state.get("severity_history", [])
    observations = state.get("monitoring_observations", [])
    monitoring_count = state.get("monitoring_count", 0) + 1

    observation_index = min(
        monitoring_count - 1,
        len(observations) - 1
    )

    current_observation = observations[observation_index]

    previous_observation = (
        observations[observation_index - 1]
        if observation_index > 0
        else raw_data
    )

    prompt = f"""
You are a cybersecurity continuous monitoring agent.

Monitor the security incident using the NEW observation.

Original security event:
{raw_data}

Previous observation:
{previous_observation}

NEW observation:
{current_observation}

Previous severity:
{severity}

Previous risk score:
{risk_score}

Severity history:
{severity_history}

Compare the previous observation with the new observation.

Determine whether the threat has increased, decreased, or remained stable.

Pay particular attention to:
1. Packet volume
2. Connection volume
3. Attack intensity
4. Expansion of suspicious activity
5. Potential increase in impact

If the new observation indicates a meaningful increase in threat activity,
classify the severity change as INCREASED.

Return exactly:

CURRENT_SEVERITY: <LOW|MEDIUM|HIGH|CRITICAL>
CURRENT_RISK_SCORE: <0-100>
SEVERITY_CHANGE: INCREASED or DECREASED or STABLE
REASON: <short explanation>
"""

    response = generate_response(prompt)

    severity_match = re.search(
        r"CURRENT_SEVERITY:\s*(LOW|MEDIUM|HIGH|CRITICAL)",
        response,
        re.IGNORECASE
    )

    score_match = re.search(
        r"CURRENT_RISK_SCORE:\s*(\d+(?:\.\d+)?)",
        response,
        re.IGNORECASE
    )

    change_match = re.search(
        r"SEVERITY_CHANGE:\s*(INCREASED|DECREASED|STABLE)",
        response,
        re.IGNORECASE
    )

    current_severity = (
        severity_match.group(1).upper()
        if severity_match
        else severity
    )

    current_risk_score = (
        float(score_match.group(1))
        if score_match
        else risk_score
    )

    severity_change = (
        change_match.group(1).upper()
        if change_match
        else "STABLE"
    )

    updated_history = severity_history + [
        {
            "stage": "monitoring",
            "cycle": monitoring_count,
            "severity": current_severity,
            "risk_score": current_risk_score,
            "change": severity_change,
            "observation": current_observation
        }
    ]

    return {
        "monitoring_result": {
            "raw_response": response,
            "severity_change": severity_change
        },
        "current_observation": current_observation,
        "severity": current_severity,
        "risk_score": current_risk_score,
        "severity_history": updated_history,
        "monitoring_count": monitoring_count,
        "response_required": severity_change == "INCREASED",
        "status": "monitoring_completed"
    }