from services.llm_service import generate_response


def response_agent(state):
    severity = state.get("severity", "HIGH")
    risk_score = state.get("risk_score", 0)
    raw_data = state.get("raw_data", {})
    monitoring_result = state.get("monitoring_result", {})

    prompt = f"""
You are an autonomous cybersecurity response agent.

A monitored security incident has increased in severity.

Security event:
{raw_data}

Current severity:
{severity}

Current risk score:
{risk_score}

Monitoring result:
{monitoring_result}

Determine an appropriate defensive response.

Consider:
1. Immediate containment
2. Blocking or isolation
3. Credential protection
4. Network restriction
5. Evidence preservation
6. Further investigation

Return exactly:

RESPONSE_ACTION: <action>
CONTAINMENT: <action>
JUSTIFICATION: <short explanation>
PRIORITY: <LOW|MEDIUM|HIGH|CRITICAL>
"""

    response = generate_response(prompt)

    return {
        "response_result": {
            "raw_response": response
        },
        "response_required": True,
        "status": "response_completed"
    }