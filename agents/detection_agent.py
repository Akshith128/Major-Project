from services.llm_service import generate_response


def detection_agent(state):
    raw_data = state.get("raw_data", {})

    prompt = f"""
You are a cybersecurity detection agent.

Analyze the following security event:

{raw_data}

Determine whether the event represents a potential cybersecurity threat.

Return the result in this exact format:

THREAT_DETECTED: YES or NO
THREAT_TYPE: <type>
CONFIDENCE: <0-100>
REASON: <short explanation>
"""

    response = generate_response(prompt)

    return {
        "detection_result": {
            "raw_response": response
        },
        "status": "detection_completed"
    }