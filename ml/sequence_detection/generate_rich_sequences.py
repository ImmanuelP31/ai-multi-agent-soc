"""
generate_rich_sequences.py
---------------------------
Generates LSTM training sequences from CICFlowMeter CSV datasets.

Saves all output to ml/sequence_detection/ using absolute paths,
so this script can be run from anywhere in the repo:

  python ml/sequence_detection/generate_rich_sequences.py   ← works
  cd ml/sequence_detection && python generate_rich_sequences.py  ← also works

Output files (all saved to same directory as this script):
  processed_sequences.npy   ← X  (samples, SEQUENCE_LENGTH, num_features)
  sequence_labels.npy       ← y  (samples,)  integer class indices
  label_mapping.json        ← { "BENIGN": 0, "DDoS": 1, ... }
  severity_mapping.json     ← { "LOW": 0, "MEDIUM": 1, ... }
  metadata.json             ← sequence_length, num_features, num_classes, dataset_size
"""

import pandas as pd
import numpy as np
import glob
import json
import os
from pathlib import Path

# ── Resolve output directory relative to THIS file, not cwd ──────────────────
THIS_DIR     = Path(__file__).resolve().parent
DATASET_PATH = THIS_DIR.parent / "datasets" / "*.csv"

SEQUENCE_LENGTH = 5

# ── Load all CSV files ────────────────────────────────────────────────────────

csv_files  = glob.glob(str(DATASET_PATH))

if not csv_files:
    raise FileNotFoundError(
        f"No CSV files found at {DATASET_PATH}.\n"
        "Download the CICIDS2017 dataset and place the CSV files in ml/datasets/."
    )

dataframes = []
for file in csv_files:
    print(f"Loading: {os.path.basename(file)}")
    df = pd.read_csv(file)
    dataframes.append(df)

combined_df = pd.concat(dataframes, ignore_index=True)
print(f"\nDatasets combined — {len(combined_df):,} rows")

# ── Clean columns ─────────────────────────────────────────────────────────────

combined_df.columns = combined_df.columns.str.strip()

selected_columns = [
    "Label",
    "Flow Packets/s",
    "Flow Bytes/s",
    "Total Fwd Packets",
    "Total Backward Packets",
]

combined_df = combined_df[selected_columns]
combined_df.replace([float("inf"), -float("inf")], 0, inplace=True)
combined_df.dropna(inplace=True)
combined_df["Label"] = combined_df["Label"].astype(str).str.strip()

# ── Label encoding ────────────────────────────────────────────────────────────
# Sort labels so the mapping is deterministic across runs,
# even if the CSV order changes.

unique_labels = sorted(combined_df["Label"].unique())
attack_mapping = {label: idx for idx, label in enumerate(unique_labels)}

with open(THIS_DIR / "label_mapping.json", "w") as f:
    json.dump(attack_mapping, f, indent=4)

print(f"\nLabel mapping ({len(attack_mapping)} classes):")
for label, idx in attack_mapping.items():
    print(f"  {idx:2d}: {label}")

combined_df["attack_encoded"] = combined_df["Label"].map(attack_mapping)

# ── Severity encoding ─────────────────────────────────────────────────────────

def assign_severity(label: str) -> str:
    if label == "BENIGN":
        return "LOW"
    if "PortScan" in label:
        return "MEDIUM"
    if any(x in label for x in ["Brute Force", "Web Attack", "Infiltration"]):
        return "HIGH"
    if any(x in label for x in ["DDoS", "DoS", "Bot", "Heartbleed"]):
        return "CRITICAL"
    return "MEDIUM"

severity_mapping = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

with open(THIS_DIR / "severity_mapping.json", "w") as f:
    json.dump(severity_mapping, f, indent=4)

combined_df["severity"]         = combined_df["Label"].apply(assign_severity)
combined_df["severity_encoded"] = combined_df["severity"].map(severity_mapping)

# ── Derived features ──────────────────────────────────────────────────────────

combined_df["anomaly_score"] = (
    combined_df["Flow Packets/s"] / (combined_df["Flow Packets/s"].max() + 1)
)
combined_df["packet_rate"]       = combined_df["Flow Packets/s"]
combined_df["attack_frequency"]  = combined_df.groupby("Label").cumcount()
combined_df["repeated_ip"]       = (combined_df["attack_frequency"] > 3).astype(int)

# ── Build feature matrix ──────────────────────────────────────────────────────

FEATURE_COLS = [
    "attack_encoded",
    "severity_encoded",
    "anomaly_score",
    "packet_rate",
    "attack_frequency",
    "repeated_ip",
]

feature_matrix = combined_df[FEATURE_COLS].values.astype(np.float32)
num_features   = len(FEATURE_COLS)

# ── Generate sliding-window sequences ────────────────────────────────────────

sequences = []
labels    = []

for i in range(len(feature_matrix) - SEQUENCE_LENGTH):
    seq        = feature_matrix[i : i + SEQUENCE_LENGTH]
    next_class = int(feature_matrix[i + SEQUENCE_LENGTH][0])   # attack_encoded of next row
    sequences.append(seq)
    labels.append(next_class)

X = np.array(sequences, dtype=np.float32)
y = np.array(labels,    dtype=np.int32)

print(f"\nSequence dataset created")
print(f"  X shape : {X.shape}   (samples, seq_len, features)")
print(f"  y shape : {y.shape}")
print(f"  Classes : {len(np.unique(y))}")

# ── Save numpy files ──────────────────────────────────────────────────────────

np.save(THIS_DIR / "processed_sequences.npy", X)
np.save(THIS_DIR / "sequence_labels.npy",     y)

# ── Save metadata — includes num_classes so train script stays in sync ────────

num_classes = len(attack_mapping)
metadata = {
    "sequence_length": SEQUENCE_LENGTH,
    "num_features":    num_features,
    "num_classes":     num_classes,
    "feature_columns": FEATURE_COLS,
    "dataset_size":    len(X),
}

with open(THIS_DIR / "metadata.json", "w") as f:
    json.dump(metadata, f, indent=4)

print(f"\nAll files saved to: {THIS_DIR}")
print("  processed_sequences.npy")
print("  sequence_labels.npy")
print("  label_mapping.json")
print("  severity_mapping.json")
print("  metadata.json")
print("\nRun train_lstm_model.py next.")