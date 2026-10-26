from pathlib import Path
import pandas as pd


SUPPORTED_EXTENSIONS = {
    ".csv",
    ".parquet"
}


def load_network_data(file_path: str) -> pd.DataFrame:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}"
        )

    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file type: {path.suffix}"
        )

    if path.suffix.lower() == ".csv":
        dataframe = pd.read_csv(path)
    else:
        dataframe = pd.read_parquet(path)

    if dataframe.empty:
        raise ValueError(
            "The dataset contains no records."
        )

    dataframe.columns = [
        str(column).strip()
        for column in dataframe.columns
    ]

    return dataframe


def find_column(
    dataframe: pd.DataFrame,
    candidates: list
) -> str:
    normalized = {
        str(column).strip().lower(): column
        for column in dataframe.columns
    }

    for candidate in candidates:
        if candidate.lower() in normalized:
            return normalized[candidate.lower()]

    for column in dataframe.columns:
        column_name = str(column).lower()

        for candidate in candidates:
            if candidate.lower() in column_name:
                return column

    raise KeyError(
        f"None of these columns were found: {candidates}"
    )


def convert_flow_to_observation(
    dataframe: pd.DataFrame
) -> dict:
    forward_packet_column = find_column(
        dataframe,
        [
            "Total Fwd Packets"
        ]
    )

    backward_packet_column = find_column(
        dataframe,
        [
            "Total Backward Packets"
        ]
    )

    flow_bytes_column = find_column(
        dataframe,
        [
            "Flow Bytes/s"
        ]
    )

    flow_packets_column = find_column(
        dataframe,
        [
            "Flow Packets/s"
        ]
    )

    syn_column = find_column(
        dataframe,
        [
            "SYN Flag Count"
        ]
    )

    rst_column = find_column(
        dataframe,
        [
            "RST Flag Count"
        ]
    )

    ack_column = find_column(
        dataframe,
        [
            "ACK Flag Count"
        ]
    )

    forward_packets = pd.to_numeric(
        dataframe[forward_packet_column],
        errors="coerce"
    ).fillna(0)

    backward_packets = pd.to_numeric(
        dataframe[backward_packet_column],
        errors="coerce"
    ).fillna(0)

    flow_bytes = pd.to_numeric(
        dataframe[flow_bytes_column],
        errors="coerce"
    ).fillna(0)

    flow_packets = pd.to_numeric(
        dataframe[flow_packets_column],
        errors="coerce"
    ).fillna(0)

    syn_flags = pd.to_numeric(
        dataframe[syn_column],
        errors="coerce"
    ).fillna(0)

    rst_flags = pd.to_numeric(
        dataframe[rst_column],
        errors="coerce"
    ).fillna(0)

    ack_flags = pd.to_numeric(
        dataframe[ack_column],
        errors="coerce"
    ).fillna(0)

    packet_count = int(
        forward_packets.sum()
        + backward_packets.sum()
    )

    connection_count = int(
        len(dataframe)
    )

    return {
        "packet_count": packet_count,
        "connection_count": connection_count,
        "average_flow_bytes_per_second": round(
            float(flow_bytes.mean()),
            2
        ),
        "average_flow_packets_per_second": round(
            float(flow_packets.mean()),
            2
        ),
        "syn_flag_count": int(
            syn_flags.sum()
        ),
        "rst_flag_count": int(
            rst_flags.sum()
        ),
        "ack_flag_count": int(
            ack_flags.sum()
        )
    }


def get_ground_truth(
    dataframe: pd.DataFrame
) -> dict:
    label_column = find_column(
        dataframe,
        [
            "Label"
        ]
    )

    labels = (
        dataframe[label_column]
        .fillna("Unknown")
        .astype(str)
        .str.strip()
    )

    label_counts = labels.value_counts().to_dict()

    attack_labels = {
        label: count
        for label, count in label_counts.items()
        if label.lower() != "benign"
    }

    attack_flow_count = sum(
        attack_labels.values()
    )

    if attack_flow_count > 0:
        dominant_attack = max(
            attack_labels,
            key=attack_labels.get
        )
        ground_truth = dominant_attack
    else:
        ground_truth = "Benign"

    return {
        "ground_truth": ground_truth,
        "label_counts": label_counts,
        "attack_flow_count": attack_flow_count,
        "total_flow_count": len(labels)
    }


def create_monitoring_observations(
    dataframe: pd.DataFrame,
    batch_size: int = 100
) -> list:
    observations = []

    label_column = find_column(
        dataframe,
        [
            "Label"
        ]
    )

    for start in range(
        0,
        len(dataframe),
        batch_size
    ):
        batch = dataframe.iloc[
            start:start + batch_size
        ]

        if batch.empty:
            continue

        observation = convert_flow_to_observation(
            batch
        )

        ground_truth = get_ground_truth(
            batch
        )

        observations.append(
            {
                "observation": observation,
                "ground_truth": ground_truth["ground_truth"],
                "label_counts": ground_truth["label_counts"],
                "dataset_flow_count": len(batch)
            }
        )

    return observations


def find_dataset_files(
    data_directory: str = "data/raw"
) -> list:
    directory = Path(
        data_directory
    )

    if not directory.exists():
        raise FileNotFoundError(
            f"Dataset directory not found: {directory}"
        )

    files = [
        file
        for file in directory.iterdir()
        if file.is_file()
        and file.suffix.lower()
        in SUPPORTED_EXTENSIONS
    ]

    return sorted(
        files,
        key=lambda file: file.name
    )


def create_all_dataset_observations(
    data_directory: str = "data/raw",
    batch_size: int = 100
) -> list:
    all_observations = []

    dataset_files = find_dataset_files(
        data_directory
    )

    if not dataset_files:
        raise FileNotFoundError(
            "No supported dataset files were found."
        )

    for dataset_file in dataset_files:
        dataframe = load_network_data(
            str(dataset_file)
        )

        observations = create_monitoring_observations(
            dataframe,
            batch_size=batch_size
        )

        for index, item in enumerate(
            observations
        ):
            all_observations.append(
                {
                    "dataset": dataset_file.name,
                    "window": index + 1,
                    "observation": item["observation"],
                    "ground_truth": item["ground_truth"],
                    "label_counts": item["label_counts"],
                    "dataset_flow_count": item[
                        "dataset_flow_count"
                    ]
                }
            )

        del dataframe

    return all_observations