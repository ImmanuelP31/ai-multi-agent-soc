import pandas as pd

df = pd.read_parquet("ml/datasets/train_dataset.parquet")

print(df["Label"].value_counts())
