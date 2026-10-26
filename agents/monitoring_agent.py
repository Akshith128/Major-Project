def calculate_percentage_change(
    previous_value,
    current_value
):
    if previous_value == 0:
        if current_value > 0:
            return 100.0
        return 0.0

    return (
        (current_value - previous_value)
        / previous_value
    ) * 100


def get_recovery_severity(
    severity,
    recovery_count
):
    severity_levels = [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]

    if severity not in severity_levels:
        return "LOW"

    current_index = severity_levels.index(
        severity
    )

    reduction = min(
        recovery_count,
        current_index
    )

    return severity_levels[
        current_index - reduction
    ]


def _valid_observation(observation):
    if not isinstance(observation, dict):
        return False

    required_fields = (
        "packet_count",
        "average_flow_packets_per_second",
        "average_flow_bytes_per_second",
        "syn_flag_count",
        "rst_flag_count",
        "ack_flag_count",
    )

    if any(
        field not in observation
        or isinstance(observation[field], bool)
        for field in required_fields
    ):
        return False

    try:
        for field in required_fields:
            float(observation[field])
    except (TypeError, ValueError):
        return False

    return True


def monitoring_agent(state):
    raw_data = state.get(
        "raw_data",
        {}
    )

    severity = state.get(
        "severity",
        "LOW"
    )

    risk_score = state.get(
        "risk_score",
        0.0
    )

    severity_history = state.get(
        "severity_history",
        []
    )

    observations = state.get(
        "monitoring_observations",
        []
    )

    monitoring_count = (
        state.get(
            "monitoring_count",
            0
        )
        + 1
    )

    previous_recovery_count = state.get(
        "recovery_count",
        0
    )

    if not observations:
        return {
            "monitoring_result": {
                "severity_change": "STABLE",
                "anomaly_detected": False,
                "reason": (
                    "No monitoring observations "
                    "are available."
                )
            },
            "monitoring_count": monitoring_count,
            "monitoring_detection_required": False,
            "response_required": False,
            "response_completed": False,
            "status": "monitoring_completed"
        }

    observation_index = min(
        monitoring_count - 1,
        len(observations) - 1
    )

    current_observation = observations[
        observation_index
    ]

    if not _valid_observation(current_observation):
        reason = (
            "Monitoring evidence is missing or malformed; "
            "recovery was not established."
        )
        severity_history = state.get(
            "severity_history",
            []
        )
        updated_history = (
            severity_history
            + [
                {
                    "stage": "monitoring",
                    "cycle": monitoring_count,
                    "severity": severity,
                    "risk_score": round(
                        risk_score,
                        2
                    ),
                    "change": "INDETERMINATE",
                    "anomaly_detected": None,
                    "evidence_valid": False,
                    "reason": reason
                }
            ]
        )
        return {
            "monitoring_result": {
                "severity_change": "INDETERMINATE",
                "anomaly_detected": None,
                "anomaly_score": None,
                "recovery_detected": False,
                "risk_increased": False,
                "evidence_valid": False,
                "reason": reason
            },
            "current_observation": current_observation,
            "severity": severity,
            "risk_score": round(
                risk_score,
                2
            ),
            "severity_history": updated_history,
            "monitoring_count": monitoring_count,
            "recovery_count": state.get(
                "recovery_count",
                0
            ),
            "monitoring_evidence_invalid": True,
            "monitoring_detection_required": False,
            "response_required": False,
            "response_completed": False,
            "status": "monitoring_evidence_invalid"
        }

    previous_observation = (
        observations[
            observation_index - 1
        ]
        if observation_index > 0
        else raw_data
    )

    previous_packets = float(
        previous_observation.get(
            "packet_count",
            0
        )
    )

    current_packets = float(
        current_observation.get(
            "packet_count",
            0
        )
    )

    previous_packet_rate = float(
        previous_observation.get(
            "average_flow_packets_per_second",
            0
        )
    )

    current_packet_rate = float(
        current_observation.get(
            "average_flow_packets_per_second",
            0
        )
    )

    previous_bytes_rate = float(
        previous_observation.get(
            "average_flow_bytes_per_second",
            0
        )
    )

    current_bytes_rate = float(
        current_observation.get(
            "average_flow_bytes_per_second",
            0
        )
    )

    current_syn = float(
        current_observation.get(
            "syn_flag_count",
            0
        )
    )

    current_rst = float(
        current_observation.get(
            "rst_flag_count",
            0
        )
    )

    current_ack = float(
        current_observation.get(
            "ack_flag_count",
            0
        )
    )

    packet_change = calculate_percentage_change(
        previous_packets,
        current_packets
    )

    packet_rate_change = calculate_percentage_change(
        previous_packet_rate,
        current_packet_rate
    )

    bytes_rate_change = calculate_percentage_change(
        previous_bytes_rate,
        current_bytes_rate
    )

    attack_indicators = []

    if current_packet_rate >= 1000:
        attack_indicators.append(
            "high packet rate"
        )

    if current_rst >= 10:
        attack_indicators.append(
            "high RST flag activity"
        )

    if current_syn >= 10:
        attack_indicators.append(
            "high SYN flag activity"
        )

    if packet_change >= 20:
        attack_indicators.append(
            "rapid packet-volume increase"
        )

    if packet_rate_change >= 20:
        attack_indicators.append(
            "rapid packet-rate increase"
        )

    if bytes_rate_change >= 50:
        attack_indicators.append(
            "rapid byte-rate increase"
        )

    anomaly_score = 0

    if current_packet_rate >= 1000:
        anomaly_score += 25

    if current_rst >= 10:
        anomaly_score += 25

    if current_syn >= 10:
        anomaly_score += 20

    if packet_change >= 20:
        anomaly_score += 10

    if packet_rate_change >= 20:
        anomaly_score += 10

    if bytes_rate_change >= 50:
        anomaly_score += 10

    anomaly_score = min(
        anomaly_score,
        100
    )

    anomaly_detected = (
        anomaly_score >= 40
    )

    recovery_detected = (
        not anomaly_detected
        and current_packet_rate < 1000
        and current_rst < 10
        and current_syn < 10
    )

    if anomaly_detected:

        severity_change = "INCREASED"

        recovery_count = 0

        if severity == "LOW":
            current_severity = "MEDIUM"
        elif severity == "MEDIUM":
            current_severity = "HIGH"
        elif severity == "HIGH":
            current_severity = "CRITICAL"
        else:
            current_severity = "CRITICAL"

        current_risk_score = min(
            100.0,
            risk_score
            + max(
                10.0,
                anomaly_score / 5
            )
        )

    elif recovery_detected:

        recovery_count = (
            previous_recovery_count
            + 1
        )

        previous_severity = severity

        current_severity = get_recovery_severity(
            severity,
            1
        )

        if current_severity != previous_severity:
            severity_change = "DECREASED"
        else:
            severity_change = "STABLE"

        current_risk_score = max(
            0.0,
            risk_score - 20.0
        )

    else:

        recovery_count = 0

        severity_change = "STABLE"

        current_severity = severity

        current_risk_score = risk_score

    if attack_indicators:

        indicator_text = ", ".join(
            attack_indicators
        )

    else:

        indicator_text = (
            "No significant anomaly indicators."
        )

    reason = (
        f"Packet count changed by "
        f"{packet_change:.2f}%. "
        f"Packet rate changed by "
        f"{packet_rate_change:.2f}%. "
        f"Byte rate changed by "
        f"{bytes_rate_change:.2f}%. "
        f"Current RST flags: "
        f"{int(current_rst)}. "
        f"Current SYN flags: "
        f"{int(current_syn)}. "
        f"Current ACK flags: "
        f"{int(current_ack)}. "
        f"Anomaly score: "
        f"{anomaly_score}/100. "
        f"Recovery count: "
        f"{recovery_count}. "
        f"Indicators: "
        f"{indicator_text}"
    )

    updated_history = (
        severity_history
        + [
            {
                "stage": "monitoring",
                "cycle": monitoring_count,
                "severity": current_severity,
                "risk_score": round(
                    current_risk_score,
                    2
                ),
                "change": severity_change,
                "anomaly_detected": (
                    anomaly_detected
                ),
                "anomaly_score": anomaly_score,
                "packet_change_percent": round(
                    packet_change,
                    2
                ),
                "packet_rate_change_percent": round(
                    packet_rate_change,
                    2
                ),
                "bytes_rate_change_percent": round(
                    bytes_rate_change,
                    2
                ),
                "syn_flag_count": int(
                    current_syn
                ),
                "rst_flag_count": int(
                    current_rst
                ),
                "ack_flag_count": int(
                    current_ack
                ),
                "recovery_count": (
                    recovery_count
                ),
                "indicators": (
                    attack_indicators
                ),
                "observation": (
                    current_observation
                )
            }
        ]
    )

    return {
        "monitoring_result": {
            "severity_change": (
                severity_change
            ),
            "anomaly_detected": (
                anomaly_detected
            ),
            "anomaly_score": (
                anomaly_score
            ),
            "packet_change_percent": round(
                packet_change,
                2
            ),
            "packet_rate_change_percent": round(
                packet_rate_change,
                2
            ),
            "bytes_rate_change_percent": round(
                bytes_rate_change,
                2
            ),
            "syn_flag_count": int(
                current_syn
            ),
            "rst_flag_count": int(
                current_rst
            ),
            "ack_flag_count": int(
                current_ack
            ),
            "indicators": (
                attack_indicators
            ),
            "recovery_detected": (
                recovery_detected
            ),
            "recovery_count": (
                recovery_count
            ),
            "evidence_valid": True,
            "risk_increased": (
                current_risk_score > risk_score
            ),
            "reason": reason
        },

        "current_observation": (
            current_observation
        ),

        "severity": current_severity,

        "risk_score": round(
            current_risk_score,
            2
        ),

        "severity_history": (
            updated_history
        ),

        "monitoring_count": (
            monitoring_count
        ),

        "recovery_count": (
            recovery_count
        ),

        "monitoring_evidence_invalid": state.get(
            "monitoring_evidence_invalid",
            False
        ),

        "monitoring_detection_required": (
            anomaly_detected
        ),

        "response_required": False,

        "response_completed": False,

        "status": "monitoring_completed"
    }