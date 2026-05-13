import pandas as pd
import numpy as np
import glob
import json
import os

# -----------------------------------
# CONFIG
# -----------------------------------

SEQUENCE_LENGTH = 5

# -----------------------------------
# LOAD DATASETS
# -----------------------------------

dataset_path = "../datasets/*.csv"

csv_files = glob.glob(dataset_path)

dataframes = []

for file in csv_files:

    print(f"Loading: {os.path.basename(file)}")

    df = pd.read_csv(file)

    dataframes.append(df)

combined_df = pd.concat(
    dataframes,
    ignore_index=True
)

print("\nDatasets Combined")

# -----------------------------------
# CLEAN COLUMNS
# -----------------------------------

combined_df.columns = combined_df.columns.str.strip()

# -----------------------------------
# KEEP IMPORTANT COLUMNS
# -----------------------------------

selected_columns = [
    "Label",
    "Flow Packets/s",
    "Flow Bytes/s",
    "Total Fwd Packets",
    "Total Backward Packets"
]

combined_df = combined_df[selected_columns]

# -----------------------------------
# CLEAN NULLS
# -----------------------------------

combined_df.replace(
    [float("inf"), -float("inf")],
    0,
    inplace=True
)

combined_df.dropna(inplace=True)

# -----------------------------------
# CLEAN LABELS
# -----------------------------------

combined_df["Label"] = (
    combined_df["Label"]
    .astype(str)
    .str.strip()
)

# -----------------------------------
# ATTACK ENCODING
# -----------------------------------

unique_labels = combined_df["Label"].unique()

attack_mapping = {
    label: idx
    for idx, label in enumerate(unique_labels)
}

# Save mapping
with open("label_mapping.json", "w") as f:
    json.dump(attack_mapping, f, indent=4)

combined_df["attack_encoded"] = combined_df[
    "Label"
].map(attack_mapping)

# -----------------------------------
# GENERATE SEVERITY
# -----------------------------------

def assign_severity(label):

    if label == "BENIGN":
        return "LOW"

    elif "PortScan" in label:
        return "MEDIUM"

    elif (
        "Brute Force" in label
        or "Web Attack" in label
        or "Infiltration" in label
    ):
        return "HIGH"

    elif (
        "DDoS" in label
        or "Bot" in label
    ):
        return "CRITICAL"

    else:
        return "MEDIUM"

combined_df["severity"] = combined_df[
    "Label"
].apply(assign_severity)

severity_mapping = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3
}

with open("severity_mapping.json", "w") as f:
    json.dump(severity_mapping, f, indent=4)

combined_df["severity_encoded"] = combined_df[
    "severity"
].map(severity_mapping)

# -----------------------------------
# CREATE ANOMALY SCORE
# -----------------------------------

combined_df["anomaly_score"] = (
    combined_df["Flow Packets/s"] /
    (
        combined_df["Flow Packets/s"].max() + 1
    )
)

# -----------------------------------
# PACKET RATE
# -----------------------------------

combined_df["packet_rate"] = combined_df[
    "Flow Packets/s"
]

# -----------------------------------
# ATTACK FREQUENCY
# -----------------------------------

combined_df["attack_frequency"] = (
    combined_df.groupby("Label")
    .cumcount()
)

# -----------------------------------
# REPEATED OFFENDER
# -----------------------------------

combined_df["repeated_ip"] = np.where(
    combined_df["attack_frequency"] > 3,
    1,
    0
)

# -----------------------------------
# BUILD FEATURE MATRIX
# -----------------------------------

feature_matrix = combined_df[
    [
        "attack_encoded",
        "severity_encoded",
        "anomaly_score",
        "packet_rate",
        "attack_frequency",
        "repeated_ip"
    ]
].values

# -----------------------------------
# CREATE SEQUENCES
# -----------------------------------

sequences = []
labels = []

for i in range(
    len(feature_matrix) - SEQUENCE_LENGTH
):

    seq = feature_matrix[
        i : i + SEQUENCE_LENGTH
    ]

    next_attack = feature_matrix[
        i + SEQUENCE_LENGTH
    ][0]

    sequences.append(seq)

    labels.append(next_attack)

X = np.array(sequences)

y = np.array(labels)

print("\nSequence Dataset Created")
print("X shape:", X.shape)
print("y shape:", y.shape)

# -----------------------------------
# SAVE FILES
# -----------------------------------

np.save("processed_sequences.npy", X)

np.save("sequence_labels.npy", y)

metadata = {
    "sequence_length": SEQUENCE_LENGTH,
    "num_features": X.shape[2]
}

with open("metadata.json", "w") as f:
    json.dump(metadata, f, indent=4)

print("\nRich sequence dataset saved successfully")