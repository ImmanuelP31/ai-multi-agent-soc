import pandas as pd
import numpy as np
import joblib

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# ==========================================
# LOAD TEST DATA
# ==========================================

print("Loading test dataset...")

df = pd.read_parquet(
    "ml/datasets/test_dataset.parquet"
)

# ==========================================
# LOAD MODEL
# ==========================================

model = joblib.load(
    "ml/models/intrusion_classifier.pkl"
)

scaler = joblib.load(
    "ml/models/intrusion_scaler.pkl"
)

features = joblib.load(
    "ml/models/intrusion_features.pkl"
)

# ==========================================
# CLEAN DATA
# ==========================================

df.columns = df.columns.str.strip()

df.replace(
    [np.inf, -np.inf],
    np.nan,
    inplace=True
)

# ==========================================
# FEATURES + LABELS
# ==========================================

X = df[features]

X = X.fillna(X.median())

y_true = df["Label"]

# ==========================================
# SCALE FEATURES
# ==========================================

X_scaled = scaler.transform(X)

# ==========================================
# PREDICTIONS
# ==========================================

print("\nRunning predictions...")

y_pred = model.predict(X_scaled)

# ==========================================
# METRICS
# ==========================================

accuracy = accuracy_score(
    y_true,
    y_pred
)

print("\n===================================")
print("CLASSIFIER EVALUATION")
print("===================================")

print(f"\nAccuracy: {accuracy:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_true,
        y_pred
    )
)

print("\nConfusion Matrix:")
print(
    confusion_matrix(
        y_true,
        y_pred
    )
)