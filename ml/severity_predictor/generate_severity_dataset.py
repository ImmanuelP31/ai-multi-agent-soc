import pandas as pd
import glob
import os

# -----------------------------------
# DATASET PATH
# -----------------------------------

dataset_path = "../datasets/*.csv"

# -----------------------------------
# LOAD ALL CSV FILES
# -----------------------------------

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

print("\nDatasets Combined Successfully")
print("Total Rows:", len(combined_df))

# -----------------------------------
# CLEAN COLUMN NAMES
# -----------------------------------

combined_df.columns = combined_df.columns.str.strip()

# -----------------------------------
# CREATE SEVERITY LABELS
# -----------------------------------

def assign_severity(row):

    label = str(row["Label"]).strip()

    # LOW
    if label == "BENIGN":
        return "LOW"

    # MEDIUM
    elif "PortScan" in label:
        return "MEDIUM"

    # HIGH
    elif (
        "Brute Force" in label
        or "Web Attack" in label
        or "Infiltration" in label
    ):
        return "HIGH"

    # CRITICAL
    elif (
        "DDoS" in label
        or "Bot" in label
    ):
        return "CRITICAL"

    else:
        return "MEDIUM"

# Apply severity labels
combined_df["severity"] = combined_df.apply(
    assign_severity,
    axis=1
)

# -----------------------------------
# SELECT IMPORTANT FEATURES
# -----------------------------------

selected_features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "severity"
]

final_df = combined_df[selected_features]

# -----------------------------------
# HANDLE INFINITE VALUES
# -----------------------------------

final_df.replace(
    [float("inf"), -float("inf")],
    0,
    inplace=True
)

# -----------------------------------
# HANDLE NULL VALUES
# -----------------------------------

final_df.dropna(inplace=True)

# -----------------------------------
# SAVE DATASET
# -----------------------------------

output_path = "severity_dataset.csv"

final_df.to_csv(output_path, index=False)

print("\nSeverity Dataset Created Successfully")
print(f"Saved to: {output_path}")