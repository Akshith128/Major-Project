from services.llm_service import generate_response


def analysis_agent(state):
    raw_data = state.get("raw_data", {})
    detection_result = state.get("detection_result", {})

    prompt = f"""
You are a cybersecurity analysis agent.

Analyze the detected security event using both the original event and the detection result.

Original security event:
{raw_data}

Detection result:
{detection_result}

Determine:

1. Attack behavior
2. Likely attack technique
3. Indicators of compromise
4. Potential impact
5. Recommended investigation focus

Return the result in this exact format:

ATTACK_BEHAVIOR: <description>
ATTACK_TECHNIQUE: <technique>
INDICATORS: <indicators>
POTENTIAL_IMPACT: <impact>
INVESTIGATION_FOCUS: <focus>
"""

    response = generate_response(prompt)

    return {
        "analysis_result": {
            "raw_response": response
        },
        "status": "analysis_completed"
    }