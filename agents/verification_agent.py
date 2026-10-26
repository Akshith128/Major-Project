def verification_agent(state):
    response_result = state.get(
        "response_result",
        {}
    )

    severity = state.get(
        "severity",
        "LOW"
    )

    risk_score = state.get(
        "risk_score",
        0
    )

    monitoring_result = state.get(
        "monitoring_result",
        {}
    )

    evidence_valid = (
        monitoring_result.get(
            "evidence_valid"
        )
        is True
    )

    severity_change = monitoring_result.get(
        "severity_change",
        "STABLE"
    )

    anomaly_detected = monitoring_result.get(
        "anomaly_detected",
        False
    )

    anomaly_score = monitoring_result.get(
        "anomaly_score",
        0
    )

    response_cycle = state.get(
        "response_cycle",
        1
    )

    monitoring_cycle = state.get(
        "monitoring_count",
        0
    )

    severity_history = state.get(
        "severity_history",
        []
    )

    previous_anomaly_score = 0

    for item in reversed(
        severity_history
    ):
        if (
            item.get("stage")
            == "monitoring"
            and item.get("cycle", 0)
            < monitoring_cycle
        ):
            previous_anomaly_score = item.get(
                "anomaly_score",
                0
            )
            break

    response_available = bool(
        response_result.get(
            "raw_response"
        )
    )

    if not evidence_valid:

        verification_status = (
            "RESPONSE_NOT_CONFIRMED"
        )

        response_effective = False

        verification_reason = (
            "Monitoring evidence was missing or malformed; "
            "response effectiveness could not be confirmed."
        )

    elif not response_available:

        verification_status = (
            "RESPONSE_NOT_CONFIRMED"
        )

        response_effective = False

        verification_reason = (
            "No response action was available "
            "for effectiveness verification."
        )

    elif not anomaly_detected:

        verification_status = (
            "RESPONSE_EFFECTIVE"
        )

        response_effective = True

        verification_reason = (
            "The post-response monitoring window "
            "does not contain a significant anomaly. "
            "The monitored threat indicators have "
            "reduced."
        )

    elif (
        severity_change == "DECREASED"
        and anomaly_score
        < previous_anomaly_score
    ):

        verification_status = (
            "RESPONSE_EFFECTIVE"
        )

        response_effective = True

        verification_reason = (
            "The post-response monitoring window "
            "shows reduced severity and a lower "
            "anomaly score."
        )

    elif (
        anomaly_detected
        and severity_change
        == "INCREASED"
    ):

        verification_status = (
            "RESPONSE_INEFFECTIVE"
        )

        response_effective = False

        verification_reason = (
            "The post-response monitoring window "
            "still contains an anomaly and the "
            "severity has increased. Additional "
            "response is required."
        )

    elif (
        anomaly_detected
        and anomaly_score
        >= previous_anomaly_score
    ):

        verification_status = (
            "RESPONSE_INEFFECTIVE"
        )

        response_effective = False

        verification_reason = (
            "The post-response monitoring window "
            "still contains significant threat "
            "indicators and the anomaly score has "
            "not decreased."
        )

    else:

        verification_status = (
            "RESPONSE_PARTIALLY_EFFECTIVE"
        )

        response_effective = False

        verification_reason = (
            "Threat indicators remain present. "
            "Additional monitoring and response "
            "are required."
        )

    updated_history = (
        severity_history
        + [
            {
                "stage": "verification",
                "cycle": response_cycle,
                "monitoring_cycle": monitoring_cycle,
                "severity": severity,
                "risk_score": risk_score,
                "anomaly_score": anomaly_score,
                "previous_anomaly_score": (
                    previous_anomaly_score
                ),
                "verification_status": (
                    verification_status
                ),
                "response_effective": (
                    response_effective
                ),
                "reason": verification_reason
            }
        ]
    )

    return {
        "verification_result": {
            "verification_status": (
                verification_status
            ),
            "response_executed": (
                response_available
            ),
            "response_effective": (
                response_effective
            ),
            "monitoring_cycle": (
                monitoring_cycle
            ),
            "anomaly_score": (
                anomaly_score
            ),
            "previous_anomaly_score": (
                previous_anomaly_score
            ),
            "reason": verification_reason
        },

        "severity_history": (
            updated_history
        ),

        "response_pending": False,

        "response_required": (
            not response_effective
        ),

        "response_completed": (
            response_available
        ),

        "status": (
            "verification_completed"
        )
    }