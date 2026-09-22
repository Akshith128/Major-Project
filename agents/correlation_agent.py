from services.llm_service import generate_response


def correlation_agent(state):
    detection_result = state.get("detection_result", {})
    analysis_result = state.get("analysis_result", {})
    raw_data = state.get("raw_data", {})

    prompt = f"""
You are a cybersecurity correlation agent.

Correlate the security event using the original event, detection result, and analysis result.

Original security event:
{raw_data}

Detection result:
{detection_result}

Analysis result:
{analysis_result}

Determine whether the available evidence is consistent with a coordinated or meaningful security incident.

Identify:

1. Related indicators
2. Relationships between observed events or indicators
3. Attack progression
4. Correlation confidence
5. Incident classification

Return the result in this exact format:

RELATED_INDICATORS: <indicators>
RELATIONSHIPS: <relationships>
ATTACK_PROGRESSION: <progression>
CORRELATION_CONFIDENCE: <0-100>
INCIDENT_CLASSIFICATION: <classification>
"""

    response = generate_response(prompt)

    return {
        "correlation_result": {
            "raw_response": response
        },
        "status": "correlation_completed"
    }