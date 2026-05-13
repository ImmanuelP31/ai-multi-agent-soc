import pandas as pd
from sklearn.model_selection import train_test_split


df = pd.read_parquet("ml/datasets/processed_dataset.parquet")

print("Dataset loaded successfully")
print("Shape:", df.shape)

X = df.drop(columns=["Label"])
y = df["Label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

train_df = X_train.copy()
train_df["Label"] = y_train

test_df = X_test.copy()
test_df["Label"] = y_test

train_df.to_parquet("ml/datasets/train_dataset.parquet")
test_df.to_parquet("ml/datasets/test_dataset.parquet")

print("\nTrain/Test split created successfully")

print(f"\nTraining samples: {len(train_df)}")
print(f"Testing samples: {len(test_df)}")