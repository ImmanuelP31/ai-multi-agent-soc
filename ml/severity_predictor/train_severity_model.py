import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.metrics import accuracy_score

# -----------------------------------
# LOAD DATASET
# -----------------------------------

df = pd.read_csv("severity_dataset.csv")

print("\nDataset Loaded Successfully")

# -----------------------------------
# FEATURES
# -----------------------------------

features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s"
]

X = df[features]

# -----------------------------------
# TARGET
# -----------------------------------

y = df["severity"]

# -----------------------------------
# TRAIN TEST SPLIT
# -----------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# -----------------------------------
# MODEL
# -----------------------------------

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

# -----------------------------------
# TRAIN MODEL
# -----------------------------------

print("\nTraining Severity Predictor...\n")

model.fit(X_train, y_train)

# -----------------------------------
# EVALUATE
# -----------------------------------

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print(f"Accuracy: {accuracy * 100:.2f}%\n")

print(classification_report(y_test, predictions))

# -----------------------------------
# SAVE MODEL
# -----------------------------------

joblib.dump(model, "severity_model.pkl")

print("Severity Model Saved Successfully")