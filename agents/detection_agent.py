from collections import defaultdict
import json
import os
import sys
import numpy as np
import joblib
from pathlib import Path

# Running `python agents/detection_agent.py` puts `agents/` on sys.path, not the repo root.
_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from kafka import KafkaConsumer, KafkaProducer
from backend.database import init_db, persist_alert

# =========================================================
# LOAD TRAINED ISOLATION FOREST MODEL
# =========================================================

_model_dir = _repo_root / "ml" / "models"

try:
    anomaly_model   = joblib.load(_model_dir / "anomaly_model.pkl")
    anomaly_scaler  = joblib.load(_model_dir / "anomaly_scaler.pkl")
    anomaly_features = joblib.load(_model_dir / "anomaly_features.pkl")
    print("✅ Isolation Forest model loaded successfully\n")
    MODEL_AVAILABLE = True
except FileNotFoundError:
    print("⚠️  Trained model not found — falling back to rule-based detection.")
    print("   Run ml/training/train_anomaly_model.py first to enable ML detection.\n")
    MODEL_AVAILABLE = False

# =========================================================
# FEATURE EXTRACTION FROM LOG EVENT
# =========================================================

# Maps each event type to realistic network-flow feature values.
# In production these would come from a real network flow collector (e.g. CICFlowMeter).
EVENT_FLOW_FEATURES = {
    "malware_detected":      [5000,  50,  200, 900000, 50, 1200, 800, 5, 40, 900],
    "privilege_escalation":  [3000,  30,  150, 700000, 40, 1000, 600, 4, 35, 800],
    "unauthorized_access":   [4000,  40,  180, 850000, 45, 1100, 700, 5, 38, 850],
    "port_scan":             [1000, 200,   10, 500000, 80,   100,  50, 2, 10, 120],
    "ddos_attempt":          [8000, 500,   50, 999999, 99,   200, 100, 8, 60, 300],
    "failed_login":          [ 500,  10,    5, 100000, 20,   400, 300, 1, 15, 380],
    "unknown":               [ 200,   5,    3,  50000, 10,   300, 200, 0, 10, 280],
}

# Feature order must exactly match what the model was trained on
FEATURE_ORDER = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "SYN Flag Count",
    "ACK Flag Count",
    "Average Packet Size",
]

def extract_features(log: dict) -> np.ndarray:
    """
    Extract a numeric feature vector from a raw log event.
    Uses actual flow values if present in the log, otherwise falls back
    to event-type defaults so the model always gets a valid input.
    """
    event = log.get("event", "unknown")
    defaults = EVENT_FLOW_FEATURES.get(event, EVENT_FLOW_FEATURES["unknown"])

    vector = []
    for i, feat in enumerate(FEATURE_ORDER):
        # Accept real network-flow values if the log carries them
        vector.append(float(log.get(feat, defaults[i])))

    return np.array(vector).reshape(1, -1)


# =========================================================
# ML-BASED SEVERITY CLASSIFICATION
# =========================================================

def ml_severity(log: dict) -> tuple[str, float]:
    """
    Run the Isolation Forest on the log's feature vector.
    Returns (severity_label, anomaly_score).

    Isolation Forest convention:
      predict() == -1  →  anomaly
      predict() ==  1  →  normal
      score_samples()  →  more negative = more anomalous
    """
    features = extract_features(log)
    scaled   = anomaly_scaler.transform(features)

    prediction    = anomaly_model.predict(scaled)[0]          # -1 or 1
    anomaly_score = anomaly_model.score_samples(scaled)[0]    # lower = more anomalous

    if prediction == -1:
        # Anomaly detected — use score depth to split HIGH vs MEDIUM
        if anomaly_score < -0.15:
            return "HIGH", anomaly_score
        else:
            return "MEDIUM", anomaly_score
    else:
        return "LOW", anomaly_score


# =========================================================
# RULE-BASED FALLBACK (used only if model not available)
# =========================================================

HIGH_SEVERITY   = ["malware_detected", "privilege_escalation", "unauthorized_access"]
MEDIUM_SEVERITY = ["port_scan", "ddos_attempt"]

def rule_severity(event: str) -> str:
    if event in HIGH_SEVERITY:
        return "HIGH"
    if event in MEDIUM_SEVERITY:
        return "MEDIUM"
    return "LOW"


# =========================================================
# KAFKA SETUP
# =========================================================

failed_login_counter = defaultdict(int)

_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")

consumer = KafkaConsumer(
    'soc_logs',
    bootstrap_servers=_bootstrap,
    auto_offset_reset='earliest',
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)

producer = KafkaProducer(
    bootstrap_servers=_bootstrap,
    value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
)

print("Detection Agent Running...\n")
init_db()

# =========================================================
# MAIN CONSUMER LOOP
# =========================================================

for message in consumer:

    log   = message.value
    event = log.get("event", "unknown")

    # ----- Severity classification -----
    if MODEL_AVAILABLE:
        severity, anomaly_score = ml_severity(log)
        detection_method = "isolation_forest"
    else:
        severity     = rule_severity(event)
        anomaly_score = None
        detection_method = "rule_based"

    # ----- Brute-force escalation (works on top of ML) -----
    ip_addr = log.get("ip")
    if event == "failed_login" and ip_addr:
        failed_login_counter[ip_addr] += 1
        if failed_login_counter[ip_addr] > 5:
            severity = "HIGH"   # escalate regardless of ML output

    # ----- Build alert -----
    alert = {
        "event":            event,
        "severity":         severity,
        "ip":               ip_addr,
        "user":             log.get("user"),
        "detection_method": detection_method,
    }

    if anomaly_score is not None:
        alert["anomaly_score"] = round(anomaly_score, 4)

    if event == "failed_login" and ip_addr:
        alert["failed_login_count"] = failed_login_counter[ip_addr]

    if "timestamp" in log:
        alert["timestamp"] = log["timestamp"]

    # ----- Publish to Kafka -----
    try:
        producer.send("soc_alerts", alert).get(timeout=15)
    except Exception as exc:
        print(
            json.dumps({"kafka_error": str(exc), "alert": alert}),
            file=sys.stderr,
            flush=True,
        )

    print(json.dumps(alert, default=str), flush=True)

    # ----- Persist to DB -----
    try:
        persist_alert(alert)
    except Exception as exc:
        print(
            json.dumps({"storage_error": str(exc), "alert": alert}),
            file=sys.stderr,
            flush=True,
        )
