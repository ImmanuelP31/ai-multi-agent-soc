import pandas as pd
import numpy as np
import joblib

from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score

# ==========================================
# LOAD TRAIN DATA
# ==========================================

print("Loading training dataset...")

df = pd.read_parquet(
    "ml/datasets/train_dataset.parquet"
)

print("Dataset loaded")
print("Shape:", df.shape)

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
# FEATURE SELECTION
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

X = df[features]

X = X.fillna(X.median())

# ==========================================
# LABELS
# ==========================================

y = df["Label"]

# ==========================================
# SCALE FEATURES
# ==========================================

print("\nScaling features...")

scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)

# ==========================================
# TRAIN XGBOOST MODEL
# ==========================================

print("\nTraining XGBoost classifier...")

model = XGBClassifier(
    n_estimators=200,
    max_depth=8,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="multi:softprob",
    eval_metric="mlogloss",
    tree_method="hist",
    random_state=42
)

model.fit(X_scaled, y)

# ==========================================
# SAVE MODEL
# ==========================================

print("\nSaving classifier...")

joblib.dump(
    model,
    "ml/models/intrusion_classifier.pkl"
)

joblib.dump(
    scaler,
    "ml/models/intrusion_scaler.pkl"
)

joblib.dump(
    features,
    "ml/models/intrusion_features.pkl"
)

print("\n===================================")
print("Intrusion classifier trained")
print("===================================")