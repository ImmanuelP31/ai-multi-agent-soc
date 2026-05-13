import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer

files = [
    "ml/datasets/Monday-WorkingHours.pcap_ISCX.csv",
    "ml/datasets/Tuesday-WorkingHours.pcap_ISCX.csv",
    "ml/datasets/Wednesday-workingHours.pcap_ISCX.csv",
    "ml/datasets/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "ml/datasets/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "ml/datasets/Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "ml/datasets/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "ml/datasets/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
]

df_list = []

for file in files:
    print(f"Loading {file}")
    temp_df = pd.read_csv(file)
    df_list.append(temp_df)

df = pd.concat(df_list, ignore_index=True)

print("\nDataset merged successfully")
print(df.shape)


df.columns = df.columns.str.strip()

df.replace([np.inf, -np.inf], np.nan, inplace=True)

df.dropna(subset=["Label"], inplace=True)

numeric_cols = df.select_dtypes(include=[np.number]).columns

imputer = SimpleImputer(strategy="median")
df[numeric_cols] = imputer.fit_transform(df[numeric_cols])

encoder = LabelEncoder()
df["Label"] = encoder.fit_transform(df["Label"])

print("\nPreprocessing completed")
print(df.head())

df.to_parquet("ml/datasets/processed_dataset.parquet")

print("\nProcessed dataset saved")