from pathlib import Path

from core.graph import build_graph
from services.data_loader import (
    load_network_data,
    create_monitoring_observations
)


DATASET_PATH = (
    Path("data/raw")
    / "Web2-Friday-23-02-2018_TrafficForML_CICFlowMeter.parquet"
)

BATCH_SIZE = 100
WINDOWS_BEFORE = 2
WINDOWS_AFTER = 5


print("\n=== LOADING REAL ATTACK SCENARIO ===")

dataframe = load_network_data(
    str(DATASET_PATH)
)

print(
    f"Dataset: {DATASET_PATH.name}"
)

print(
    f"Total flows: {len(dataframe)}"
)


label_column = "Label"

attack_mask = (
    dataframe[label_column]
    .fillna("Unknown")
    .astype(str)
    .str.strip()
    .str.lower()
    != "benign"
)

attack_indices = dataframe.index[
    attack_mask
].tolist()

if not attack_indices:
    raise RuntimeError(
        "No attack flows were found."
    )

first_attack_index = attack_indices[0]

start_index = max(
    0,
    (
        first_attack_index // BATCH_SIZE
        - WINDOWS_BEFORE
    ) * BATCH_SIZE
)

end_index = min(
    len(dataframe),
    (
        first_attack_index // BATCH_SIZE
        + WINDOWS_AFTER
        + 1
    ) * BATCH_SIZE
)

sample_dataframe = dataframe.iloc[
    start_index:end_index
].copy()

monitoring_data = create_monitoring_observations(
    sample_dataframe,
    batch_size=BATCH_SIZE
)

print("\n=== ATTACK SCENARIO ===")

for index, item in enumerate(
    monitoring_data,
    start=1
):
    print(
        f"Window {index}: "
        f"{item['ground_truth']}"
    )

monitoring_observations = [
    item["observation"]
    for item in monitoring_data
]

ground_truth_sequence = [
    item["ground_truth"]
    for item in monitoring_data
]

initial_observation = (
    monitoring_observations[0]
)

initial_ground_truth = (
    ground_truth_sequence[0]
)


print("\n=== INITIAL GROUND TRUTH ===")
print(initial_ground_truth)

print("\n=== INITIAL OBSERVATION ===")
print(initial_observation)

print("\n=== IMPORTANT ===")
print(
    "Ground truth is NOT provided to the agents."
)

print("\n=== ARCHITECTURE ===")
print(
    "Monitoring -> Detection -> Analysis -> "
    "Correlation -> Risk -> Response -> "
    "Monitoring -> Verification -> "
    "Monitoring -> Final Decision"
)


graph = build_graph()

initial_state = {
    "event_id": "CICFLOW-WEB2-ATTACK-001",

    "timestamp": (
        "2026-09-22T16:00:00"
    ),

    "raw_data": initial_observation,

    "monitoring_observations": (
        monitoring_observations
    ),

    "ground_truth": initial_ground_truth,

    "ground_truth_sequence": (
        ground_truth_sequence
    ),

    "monitoring_count": 0,

    "severity": "LOW",

    "risk_score": 0.0,

    "recovery_count": 0,

    "severity_history": [],

    "detection_history": [],

    "response_history": [],

    "response_pending": False,

    "response_required": False,

    "response_completed": False,

    "response_cycle": 0,

    "status": "started"
}


print("\n=== STARTING AGENT GRAPH ===")

result = graph.invoke(
    initial_state
)


print("\n=== DETECTION HISTORY ===")

detection_history = result.get(
    "detection_history",
    []
)

if detection_history:

    for item in detection_history:

        print(
            f"\nDetection Cycle: "
            f"{item['monitoring_cycle']}"
        )

        print(
            item["raw_response"]
        )

else:

    print(
        "Detection not triggered."
    )


print("\n=== ANALYSIS RESULT ===")

if result.get(
    "analysis_result"
):

    print(
        result[
            "analysis_result"
        ][
            "raw_response"
        ]
    )

else:

    print(
        "Analysis not triggered."
    )


print("\n=== CORRELATION RESULT ===")

if result.get(
    "correlation_result"
):

    print(
        result[
            "correlation_result"
        ][
            "raw_response"
        ]
    )

else:

    print(
        "Correlation not triggered."
    )


print("\n=== RISK RESULT ===")

if result.get(
    "risk_result"
):

    print(
        result[
            "risk_result"
        ][
            "raw_response"
        ]
    )

else:

    print(
        "Risk assessment not triggered."
    )


print("\n=== SEVERITY HISTORY ===")

for item in result.get(
    "severity_history",
    []
):

    print(item)


print("\n=== RESPONSE HISTORY ===")

response_history = result.get(
    "response_history",
    []
)

if response_history:

    for item in response_history:

        print(
            f"\nResponse Cycle: "
            f"{item['response_cycle']}"
        )

        print(
            f"Monitoring Cycle: "
            f"{item['monitoring_cycle']}"
        )

        print(
            f"Severity: "
            f"{item['severity']}"
        )

        print(
            f"Risk Score: "
            f"{item['risk_score']}"
        )

        print(
            item["raw_response"]
        )

else:

    print(
        "Response not triggered."
    )


print("\n=== VERIFICATION HISTORY ===")

verification_history = [
    item
    for item in result.get(
        "severity_history",
        []
    )
    if item.get(
        "stage"
    ) == "verification"
]

if verification_history:

    for item in verification_history:

        print(item)

else:

    print(
        "Verification not triggered."
    )


print("\n=== FINAL VERIFICATION ===")

if result.get(
    "verification_result"
):

    print(
        result[
            "verification_result"
        ]
    )

else:

    print(
        "No final verification result."
    )


print("\n=== GROUND TRUTH SEQUENCE ===")

for index, label in enumerate(
    ground_truth_sequence,
    start=1
):

    print(
        f"Window {index}: {label}"
    )


print("\n=== FINAL MONITORING COUNT ===")

print(
    result.get(
        "monitoring_count",
        0
    )
)


print("\n=== FINAL RECOVERY COUNT ===")

print(
    result.get(
        "recovery_count",
        0
    )
)


print("\n=== FINAL SEVERITY ===")

print(
    result.get(
        "severity"
    )
)


print("\n=== FINAL RISK SCORE ===")

print(
    result.get(
        "risk_score"
    )
)


print("\n=== FINAL DECISION ===")

print(
    result.get(
        "final_decision",
        "NOT_AVAILABLE"
    )
)


print("\n=== FINAL DECISION REASON ===")

print(
    result.get(
        "final_decision_reason",
        "No final decision reason available."
    )
)


print("\n=== FINAL RESPONSE CYCLE ===")

print(
    result.get(
        "response_cycle",
        0
    )
)


print("\n=== FINAL STATUS ===")

print(
    result.get(
        "status"
    )
)