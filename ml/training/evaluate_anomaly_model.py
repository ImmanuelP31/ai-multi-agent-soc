import pandas as pd
import numpy as np
import joblib

from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)

# ==========================================
# LOAD TEST DATASET
# ==========================================

print("Loading test dataset...")

df = pd.read_parquet("ml/datasets/test_dataset.parquet")

print("Dataset loaded successfully")
print("Shape:", df.shape)

# ==========================================
# CLEAN COLUMN NAMES
# ==========================================

df.columns = df.columns.str.strip()

# ==========================================
# LOAD SAVED MODEL ARTIFACTS
# ==========================================

print("\nLoading trained model...")

model = joblib.load("ml/models/anomaly_model.pkl")

scaler = joblib.load("ml/models/anomaly_scaler.pkl")

features = joblib.load("ml/models/anomaly_features.pkl")

# ==========================================
# PREPARE FEATURES
# ==========================================

X = df[features]

X = X.replace([np.inf, -np.inf], np.nan)

X = X.fillna(X.median())

# ==========================================
# SCALE FEATURES
# ==========================================

X_scaled = scaler.transform(X)

# ==========================================
# PREPARE LABELS
# ==========================================

# IMPORTANT:
# In CICIDS2017:
# BENIGN traffic = normal
# everything else = anomaly

# Convert labels into:
# 0 = normal
# 1 = anomaly

y_true = (df["Label"] != 0).astype(int)

# ==========================================
# MODEL PREDICTIONS
# ==========================================

print("\nRunning inference...")

predictions = model.predict(X_scaled)

# Isolation Forest:
#  1  = normal
# -1  = anomaly

y_pred = np.where(predictions == -1, 1, 0)

# ==========================================
# EVALUATION METRICS
# ==========================================

print("\n===================================")
print("MODEL EVALUATION")
print("===================================\n")

accuracy = accuracy_score(y_true, y_pred)

precision = precision_score(
    y_true,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_true,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_true,
    y_pred,
    zero_division=0
)

cm = confusion_matrix(y_true, y_pred)

print(f"Accuracy:  {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")
print(f"F1 Score:  {f1:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(
    classification_report(
        y_true,
        y_pred,
        zero_division=0
    )
)

# ==========================================
# FALSE POSITIVE ANALYSIS
# ==========================================

tn, fp, fn, tp = cm.ravel()

false_positive_rate = fp / (fp + tn)

print("\n===================================")
print("FALSE POSITIVE ANALYSIS")
print("===================================\n")

print(f"False Positives: {fp}")
print(f"False Positive Rate: {false_positive_rate:.4f}")

# ==========================================
# DETECTION RATE
# ==========================================

detection_rate = tp / (tp + fn)

print("\n===================================")
print("ANOMALY DETECTION")
print("===================================\n")

print(f"Detected Attacks: {tp}")
print(f"Missed Attacks:   {fn}")
print(f"Detection Rate:   {detection_rate:.4f}")

print("\nEvaluation completed successfully")