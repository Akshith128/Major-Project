from services.llm_service import generate_response


def detection_agent(state):
    current_observation = state.get(
        "current_observation",
        {}
    )

    monitoring_result = state.get(
        "monitoring_result",
        {}
    )

    monitoring_cycle = state.get(
        "monitoring_count",
        0
    )

    prompt = f"""
You are a cybersecurity detection agent.

Analyze ONLY the current monitoring observation that triggered detection.

Monitoring cycle:
{monitoring_cycle}

Current network observation:
{current_observation}

Monitoring assessment:
{monitoring_result}

Determine whether this observation represents a potential cybersecurity threat.

Do not use any dataset label or ground-truth information.

Consider:
1. Packet behavior
2. Packet rate
3. Byte rate
4. SYN activity
5. RST activity
6. ACK activity
7. Sudden changes from previous traffic
8. Possible scanning, brute force, denial-of-service, exploitation, or other malicious behavior

Return the result in this exact format:

THREAT_DETECTED: YES or NO
THREAT_TYPE: <type>
CONFIDENCE: <0-100>
REASON: <short explanation>
"""

    response = generate_response(
        prompt
    )

    detection_history = state.get(
        "detection_history",
        []
    )

    updated_history = (
        detection_history
        + [
            {
                "monitoring_cycle": (
                    monitoring_cycle
                ),
                "observation": (
                    current_observation
                ),
                "monitoring_result": (
                    monitoring_result
                ),
                "raw_response": response
            }
        ]
    )

    return {
        "detection_result": {
            "raw_response": response,
            "monitoring_cycle": (
                monitoring_cycle
            )
        },

        "detection_history": (
            updated_history
        ),

        "status": "detection_completed"
    }