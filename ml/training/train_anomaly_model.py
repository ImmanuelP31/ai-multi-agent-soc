import pandas as pd
import numpy as np
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ==========================================
# LOAD TRAINING DATASET
# ==========================================

print("Loading training dataset...")

df = pd.read_parquet("ml/datasets/train_dataset.parquet")

# ==========================================
# TRAIN ONLY ON BENIGN TRAFFIC
# ==========================================

print("\nFiltering BENIGN traffic only...")

df = df[df["Label"] == 0]

print("Filtered dataset shape:", df.shape)

print("Dataset loaded successfully")

# ==========================================
# CLEAN COLUMN NAMES
# ==========================================

df.columns = df.columns.str.strip()

# ==========================================
# REMOVE INVALID VALUES
# ==========================================

df.replace([np.inf, -np.inf], np.nan, inplace=True)

# ==========================================
# SELECT IMPORTANT FEATURES
# ==========================================

features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "SYN Flag Count",
    "ACK Flag Count",
    "Average Packet Size"
]

# Keep only selected columns
X = df[features]

# ==========================================
# HANDLE MISSING VALUES
# ==========================================

X = X.fillna(X.median())

# ==========================================
# FEATURE SCALING
# ==========================================

print("\nScaling features...")

scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)

# ==========================================
# TRAIN ISOLATION FOREST
# ==========================================

print("\nTraining Isolation Forest model...")

model = IsolationForest(
    n_estimators=100,
    contamination=0.02,
    random_state=42,
    n_jobs=-1,
    verbose=1
)

model.fit(X_scaled)

# ==========================================
# SAVE MODEL
# ==========================================

print("\nSaving model...")

joblib.dump(
    model,
    "ml/models/anomaly_model.pkl"
)

joblib.dump(
    scaler,
    "ml/models/anomaly_scaler.pkl"
)

joblib.dump(
    features,
    "ml/models/anomaly_features.pkl"
)

print("\n===================================")
print("Anomaly model trained successfully")
print("===================================")