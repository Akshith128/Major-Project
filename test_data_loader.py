from pathlib import Path

from services.data_loader import (
    load_network_data,
    create_monitoring_observations
)


DATA_DIRECTORY = Path(
    "data/raw"
)

DATASET_PATH = (
    DATA_DIRECTORY
    / "Web2-Friday-23-02-2018_TrafficForML_CICFlowMeter.parquet"
)

BATCH_SIZE = 100
WINDOWS_BEFORE = 2
WINDOWS_AFTER = 5


print("\n=== LOADING DATASET ===")
print(DATASET_PATH.name)

dataframe = load_network_data(
    str(DATASET_PATH)
)

print("\n=== DATASET SHAPE ===")
print(dataframe.shape)

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
        "No attack flows were found in the dataset."
    )

first_attack_index = attack_indices[0]

print("\n=== FIRST ATTACK FLOW ===")
print(
    f"Dataset row index: {first_attack_index}"
)

print(
    f"Attack label: "
    f"{dataframe.loc[first_attack_index, label_column]}"
)

start_index = max(
    0,
    (first_attack_index // BATCH_SIZE - WINDOWS_BEFORE)
    * BATCH_SIZE
)

end_index = min(
    len(dataframe),
    (
        first_attack_index // BATCH_SIZE
        + WINDOWS_AFTER
        + 1
    )
    * BATCH_SIZE
)

sample_dataframe = dataframe.iloc[
    start_index:end_index
].copy()

print("\n=== SELECTED REGION ===")
print(
    f"Rows: {start_index} to {end_index - 1}"
)

print(
    f"Total rows: {len(sample_dataframe)}"
)

observations = create_monitoring_observations(
    sample_dataframe,
    batch_size=BATCH_SIZE
)

print("\n=== ATTACK TEST WINDOWS ===")

for index, item in enumerate(
    observations,
    start=1
):
    print(
        f"\nWindow {index}"
    )

    print(
        f"Ground Truth: "
        f"{item['ground_truth']}"
    )

    print(
        f"Labels: "
        f"{item['label_counts']}"
    )

    print(
        f"Observation: "
        f"{item['observation']}"
    )

print("\n=== TEST COMPLETED ===")