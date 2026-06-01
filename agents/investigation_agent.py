"""
Investigation Agent
-------------------
Consumes alerts from `soc_alerts` and enriches each alert with:
  - next-attack sequence prediction
  - confidence score
  - human-readable investigation summary

The trained LSTM model is required for next-attack prediction. If
`ml/sequence_detection/sequence_model.h5` cannot be loaded, the agent keeps the
alert pipeline alive but does not emit a fallback prediction.
"""

from __future__ import annotations

import json
import os
import sys
from collections import deque
from pathlib import Path

import numpy as np
from kafka import KafkaConsumer, KafkaProducer

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

# =========================================================
# LOAD MODEL + MAPPINGS DYNAMICALLY
# =========================================================

_seq_dir = _repo_root / "ml" / "sequence_detection"

MODEL_AVAILABLE = False
MODEL_STATUS = "not_loaded"
MODEL_ERROR_MESSAGE = ""
lstm_model = None
LABEL_MAPPING: dict[int, str] = {}
SEQUENCE_LENGTH = 5
NUM_FEATURES = 6

_meta_path = _seq_dir / "metadata.json"
if _meta_path.exists():
    with open(_meta_path) as f:
        _meta = json.load(f)
    SEQUENCE_LENGTH = _meta.get("sequence_length", 5)
    NUM_FEATURES = _meta.get("num_features", 6)
    print(f"Sequence config: length={SEQUENCE_LENGTH}, features={NUM_FEATURES}")
else:
    print("WARNING: metadata.json not found - using defaults (len=5, feat=6)")

_label_path = _seq_dir / "label_mapping.json"
if _label_path.exists():
    with open(_label_path) as f:
        _raw_mapping = json.load(f)
    LABEL_MAPPING = {int(v): k for k, v in _raw_mapping.items()}
    print(f"Label mapping loaded: {len(LABEL_MAPPING)} classes")
else:
    print("WARNING: label_mapping.json not found - predictions will show raw class index")

_model_path = _seq_dir / "sequence_model.h5"
if _model_path.exists():
    try:
        from tensorflow.keras.models import load_model  # type: ignore

        lstm_model = load_model(str(_model_path))
        actual_shape = lstm_model.input_shape
        expected_shape = (None, SEQUENCE_LENGTH, NUM_FEATURES)

        if actual_shape != expected_shape:
            MODEL_STATUS = "shape_mismatch"
            MODEL_ERROR_MESSAGE = (
                f"Sequence model shape mismatch. Model expects {actual_shape}, "
                f"but metadata says {expected_shape}. Rebuild or replace "
                f"{_model_path}."
            )
            print(f"WARNING: {MODEL_ERROR_MESSAGE}")
        else:
            MODEL_AVAILABLE = True
            MODEL_STATUS = "loaded"
            print("LSTM sequence model loaded successfully\n")
    except Exception as exc:
        MODEL_STATUS = "load_error"
        MODEL_ERROR_MESSAGE = (
            f"Could not load trained sequence model at {_model_path}: {exc}"
        )
        print(f"WARNING: {MODEL_ERROR_MESSAGE}\n")
else:
    MODEL_STATUS = "missing_model_file"
    MODEL_ERROR_MESSAGE = (
        f"Trained sequence model file is missing. Expected file: {_model_path}. "
        "Add the model file manually or run ml/sequence_detection/train_lstm_model.py, "
        "then restart the investigation agent."
    )
    print(f"WARNING: {MODEL_ERROR_MESSAGE}\n")

# =========================================================
# ATTACK CONTEXT
# =========================================================

ATTACK_CONTEXT = {
    "BENIGN": "No malicious pattern detected in recent sequence.",
    "DDoS": "DDoS attack pattern predicted - initiate traffic rate-limiting immediately.",
    "PortScan": "Port scanning behaviour detected - potential reconnaissance in progress.",
    "Bot": "Bot activity predicted - host may be part of a botnet.",
    "Infiltration": "Infiltration sequence detected - lateral movement may be underway.",
    "Web Attack \ufffd Brute Force": "Brute force sequence detected - consider account lockout and IP block.",
    "Web Attack \ufffd XSS": "XSS attack sequence predicted - review web application firewall rules.",
    "Web Attack \ufffd Sql Injection": "SQL injection sequence detected - database integrity at risk.",
    "FTP-Patator": "FTP brute force predicted - restrict FTP access and rotate credentials.",
    "SSH-Patator": "SSH brute force predicted - enforce key-based auth and block IP.",
    "DoS slowloris": "Slowloris DoS predicted - connection timeout tuning recommended.",
    "DoS Slowhttptest": "Slow HTTP DoS predicted - review server request timeout settings.",
    "DoS Hulk": "Hulk DoS attack predicted - high-volume flood imminent.",
    "DoS GoldenEye": "GoldenEye DoS predicted - application-layer flood likely.",
    "Heartbleed": "Heartbleed exploit sequence detected - patch OpenSSL immediately.",
}


def get_context(attack_name: str) -> str:
    if attack_name in ATTACK_CONTEXT:
        return ATTACK_CONTEXT[attack_name]

    for key, msg in ATTACK_CONTEXT.items():
        if key.lower() in attack_name.lower():
            return msg

    return f"Unknown attack pattern predicted: '{attack_name}' - manual analyst review required."


# =========================================================
# SLIDING WINDOW
# =========================================================

ip_windows: dict[str, deque] = {}

# Feature columns:
# [attack_encoded, severity_encoded, anomaly_score, packet_rate, attack_frequency, repeated_ip]
EVENT_FEATURE_VECTOR = {
    "malware_detected": [4, 2, 0.80, 8000, 5, 1],
    "privilege_escalation": [5, 2, 0.85, 7000, 4, 1],
    "unauthorized_access": [6, 2, 0.75, 6000, 3, 0],
    "port_scan": [2, 1, 0.40, 9000, 10, 0],
    "ddos_attempt": [1, 3, 0.95, 15000, 8, 1],
    "failed_login": [0, 0, 0.20, 2000, 2, 0],
    "unknown": [0, 0, 0.10, 500, 0, 0],
}

def _align_vector(vec: list) -> list:
    if len(vec) >= NUM_FEATURES:
        return vec[:NUM_FEATURES]
    return vec + [0.0] * (NUM_FEATURES - len(vec))


def get_feature_vector(alert: dict) -> list:
    base = EVENT_FEATURE_VECTOR.get(
        alert.get("event", "unknown"),
        EVENT_FEATURE_VECTOR["unknown"],
    )
    return _align_vector(base)


def update_window(ip: str, alert: dict) -> deque:
    if ip not in ip_windows:
        ip_windows[ip] = deque(maxlen=SEQUENCE_LENGTH)

    ip_windows[ip].append(get_feature_vector(alert))

    return ip_windows[ip]


def predict_next_attack(window: deque) -> tuple[str, float]:
    seq = list(window)
    while len(seq) < SEQUENCE_LENGTH:
        seq.insert(0, [0.0] * NUM_FEATURES)

    x = np.array(seq, dtype=np.float32).reshape(1, SEQUENCE_LENGTH, NUM_FEATURES)
    probs = lstm_model.predict(x, verbose=0)[0]
    idx = int(np.argmax(probs))
    conf = float(probs[idx])
    name = LABEL_MAPPING.get(idx, f"class_{idx}")
    return name, conf


# =========================================================
# KAFKA SETUP
# =========================================================

_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")

consumer = KafkaConsumer(
    "soc_alerts",
    bootstrap_servers=_bootstrap,
    auto_offset_reset="earliest",
    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
)

producer = KafkaProducer(
    bootstrap_servers=_bootstrap,
    value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
)

print("Investigation Agent Running...\n")

# =========================================================
# MAIN CONSUMER LOOP
# =========================================================

for message in consumer:
    alert = message.value
    ip = alert.get("ip") or "unknown"
    window = update_window(ip, alert)

    if MODEL_AVAILABLE:
        predicted_attack, conf = predict_next_attack(window)
        summary = get_context(predicted_attack)

        alert["predicted_next_attack"] = predicted_attack
        alert["confidence"] = round(conf, 4)
        alert["investigation"] = (
            f"{summary} "
            f"(LSTM predicted '{predicted_attack}' with {conf * 100:.1f}% "
            f"confidence based on last {len(window)} events from {ip}.)"
        )
        alert["investigation_method"] = "lstm_sequence_model"
        alert["lstm_status"] = MODEL_STATUS
    else:
        alert["predicted_next_attack"] = None
        alert["confidence"] = None
        alert["investigation"] = (
            "Next-attack prediction unavailable because the trained LSTM "
            f"sequence model is not loaded. Status: '{MODEL_STATUS}'. "
            f"{MODEL_ERROR_MESSAGE}"
        )
        alert["investigation_method"] = "lstm_sequence_model_unavailable"
        alert["lstm_status"] = MODEL_STATUS

    producer.send("investigated_alerts", alert)
    print(json.dumps(alert, default=str), flush=True)
