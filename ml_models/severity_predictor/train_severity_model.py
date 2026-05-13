import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

# Load dataset
df = pd.read_csv("severity_dataset.csv")

# Features
features = [
    "anomaly_score",
    "confidence_score",
    "packet_rate",
    "failed_logins",
    "attack_frequency"
]

X = df[features]

# Labels
y = df["severity"]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Train model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

# Evaluate
preds = model.predict(X_test)

print(classification_report(y_test, preds))

# Save model
joblib.dump(model, "severity_model.pkl")

print("Severity model trained successfully")