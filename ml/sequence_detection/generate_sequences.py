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

# -----------------------------------
# COMBINE DATASETS
# -----------------------------------

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
# KEEP LABEL COLUMN
# -----------------------------------

combined_df = combined_df[["Label"]]

# -----------------------------------
# CLEAN LABELS
# -----------------------------------

combined_df["Label"] = (
    combined_df["Label"]
    .astype(str)
    .str.strip()
)

# -----------------------------------
# CREATE LABEL MAPPING
# -----------------------------------

unique_labels = combined_df["Label"].unique()

label_mapping = {
    label: idx
    for idx, label in enumerate(unique_labels)
}

print("\nLabel Mapping:")
print(label_mapping)

# Save mapping
with open("label_mapping.json", "w") as f:
    json.dump(label_mapping, f, indent=4)

# -----------------------------------
# ENCODE LABELS
# -----------------------------------

combined_df["encoded"] = combined_df["Label"].map(
    label_mapping
)

encoded_events = combined_df["encoded"].tolist()

# -----------------------------------
# CREATE SEQUENCES
# -----------------------------------

sequences = []
labels = []

for i in range(len(encoded_events) - SEQUENCE_LENGTH):

    seq = encoded_events[
        i : i + SEQUENCE_LENGTH
    ]

    next_event = encoded_events[
        i + SEQUENCE_LENGTH
    ]

    sequences.append(seq)

    labels.append(next_event)

# -----------------------------------
# CONVERT TO NUMPY
# -----------------------------------

X = np.array(sequences)

y = np.array(labels)

print("\nSequence Dataset Created")
print("X shape:", X.shape)
print("y shape:", y.shape)

# -----------------------------------
# SAVE NUMPY FILES
# -----------------------------------

np.save("processed_sequences.npy", X)

np.save("sequence_labels.npy", y)

print("\nSaved sequence files successfully")