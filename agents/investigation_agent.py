"""
Investigation Agent
--------------------
Consumes alerts from `soc_alerts`, enriches each one with:
  - LSTM-predicted next attack in the sequence (if model available)
  - Confidence score from the softmax output
  - Human-readable investigation summary built from model output

Reads label_mapping.json and metadata.json dynamically — never hardcodes
class indices or feature counts, so it stays in sync with whatever model
was trained by generate_rich_sequences.py + train_lstm_model.py.

Falls back to rule-based investigation if sequence_model.h5 is not found.
"""

import json
import os
import sys
import numpy as np
from collections import deque
from pathlib import Path

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from kafka import KafkaConsumer, KafkaProducer

# =========================================================
# LOAD MODEL + MAPPINGS DYNAMICALLY
# =========================================================

_seq_dir = _repo_root / "ml" / "sequence_detection"

MODEL_AVAILABLE  = False
lstm_model       = None
LABEL_MAPPING    = {}   # index → attack name  (reversed from label_mapping.json)
SEQUENCE_LENGTH  = 5    # overridden by metadata.json
NUM_FEATURES     = 6    # overridden by metadata.json

# --- Read metadata.json (sequence_length, num_features) ---
_meta_path = _seq_dir / "metadata.json"
if _meta_path.exists():
    with open(_meta_path) as f:
        _meta = json.load(f)
    SEQUENCE_LENGTH = _meta.get("sequence_length", 5)
    NUM_FEATURES    = _meta.get("num_features", 6)
    print(f"Sequence config: length={SEQUENCE_LENGTH}, features={NUM_FEATURES}")
else:
    print("WARNING: metadata.json not found — using defaults (len=5, feat=6)")

# --- Read label_mapping.json (attack_name → class_index) ---
_label_path = _seq_dir / "label_mapping.json"
if _label_path.exists():
    with open(_label_path) as f:
        _raw_mapping = json.load(f)
    # Reverse: class_index (int) → attack_name (str)
    LABEL_MAPPING = {int(v): k for k, v in _raw_mapping.items()}
    print(f"Label mapping loaded: {len(LABEL_MAPPING)} classes")
else:
    print("WARNING: label_mapping.json not found — predictions will show raw class index")

# --- Load LSTM model ---
try:
    from tensorflow.keras.models import load_model  # type: ignore
    _model_path = _seq_dir / "sequence_model.h5"
    if _model_path.exists():
        lstm_model = load_model(str(_model_path))

        # Sanity check: model input shape vs metadata
        actual_shape   = lstm_model.input_shape   # (None, seq_len, num_feat)
        expected_shape = (None, SEQUENCE_LENGTH, NUM_FEATURES)
        if actual_shape != expected_shape:
            print(
                f"WARNING: Shape mismatch — model expects {actual_shape}, "
                f"but metadata says {expected_shape}.\n"
                f"Re-run generate_rich_sequences.py then train_lstm_model.py "
                f"to rebuild a consistent model."
            )
        else:
            MODEL_AVAILABLE = True
            print("LSTM sequence model loaded successfully\n")
    else:
        print("WARNING: sequence_model.h5 not found — run train_lstm_model.py first.\n")
except Exception as e:
    print(f"WARNING: Could not load LSTM model: {e}\n")

# =========================================================
# ATTACK CONTEXT
# Maps predicted attack name → investigation summary.
# Keys must match the labels in label_mapping.json exactly.
# =========================================================

ATTACK_CONTEXT = {
    "BENIGN":                       "No malicious pattern detected in recent sequence.",
    "DDoS":                         "DDoS attack pattern predicted — initiate traffic rate-limiting immediately.",
    "PortScan":                     "Port scanning behaviour detected — potential reconnaissance in progress.",
    "Bot":                          "Bot activity predicted — host may be part of a botnet.",
    "Infiltration":                 "Infiltration sequence detected — lateral movement may be underway.",
    "Web Attack \ufffd Brute Force": "Brute force sequence detected — consider account lockout and IP block.",
    "Web Attack \ufffd XSS":         "XSS attack sequence predicted — review web application firewall rules.",
    "Web Attack \ufffd Sql Injection":"SQL injection sequence detected — database integrity at risk.",
    "FTP-Patator":                  "FTP brute force predicted — restrict FTP access and rotate credentials.",
    "SSH-Patator":                  "SSH brute force predicted — enforce key-based auth and block IP.",
    "DoS slowloris":                "Slowloris DoS predicted — connection timeout tuning recommended.",
    "DoS Slowhttptest":             "Slow HTTP DoS predicted — review server request timeout settings.",
    "DoS Hulk":                     "Hulk DoS attack predicted — high-volume flood imminent.",
    "DoS GoldenEye":                "GoldenEye DoS predicted — application-layer flood likely.",
    "Heartbleed":                   "Heartbleed exploit sequence detected — patch OpenSSL immediately.",
}

def get_context(attack_name: str) -> str:
    if attack_name in ATTACK_CONTEXT:
        return ATTACK_CONTEXT[attack_name]
    # Partial match for label variants
    for key, msg in ATTACK_CONTEXT.items():
        if key.lower() in attack_name.lower():
            return msg
    return f"Unknown attack pattern predicted: '{attack_name}' — manual analyst review required."

# =========================================================
# SLIDING WINDOW — one deque per source IP
# =========================================================

ip_windows: dict[str, deque] = {}

# Maps event name → feature vector matching generate_rich_sequences.py columns:
# [attack_encoded, severity_encoded, anomaly_score, packet_rate, attack_frequency, repeated_ip]
# These are live-event approximations — real values come from network flow capture.
EVENT_FEATURE_VECTOR = {
    "malware_detected":      [4, 2, 0.80, 8000,  5, 1],
    "privilege_escalation":  [5, 2, 0.85, 7000,  4, 1],
    "unauthorized_access":   [6, 2, 0.75, 6000,  3, 0],
    "port_scan":             [2, 1, 0.40, 9000, 10, 0],
    "ddos_attempt":          [1, 3, 0.95, 15000, 8, 1],
    "failed_login":          [0, 0, 0.20, 2000,  2, 0],
    "unknown":               [0, 0, 0.10,  500,  0, 0],
}

def _align_vector(vec: list) -> list:
    """Trim or zero-pad to exactly NUM_FEATURES so it always matches the model."""
    if len(vec) >= NUM_FEATURES:
        return vec[:NUM_FEATURES]
    return vec + [0.0] * (NUM_FEATURES - len(vec))

def get_feature_vector(alert: dict) -> list:
    base = EVENT_FEATURE_VECTOR.get(
        alert.get("event", "unknown"),
        EVENT_FEATURE_VECTOR["unknown"]
    )
    return _align_vector(base)

def update_window(ip: str, alert: dict) -> deque:
    if ip not in ip_windows:
        ip_windows[ip] = deque(maxlen=SEQUENCE_LENGTH)
    ip_windows[ip].append(get_feature_vector(alert))
    return ip_windows[ip]

def predict_next_attack(window: deque) -> tuple[str, float]:
    """
    Left-pad window to SEQUENCE_LENGTH with zero vectors if not full yet.
    Returns (predicted_attack_name, confidence_score).
    """
    seq = list(window)
    while len(seq) < SEQUENCE_LENGTH:
        seq.insert(0, [0.0] * NUM_FEATURES)

    x     = np.array(seq, dtype=np.float32).reshape(1, SEQUENCE_LENGTH, NUM_FEATURES)
    probs = lstm_model.predict(x, verbose=0)[0]
    idx   = int(np.argmax(probs))
    conf  = float(probs[idx])
    name  = LABEL_MAPPING.get(idx, f"class_{idx}")  # safe fallback if index not in mapping
    return name, conf

# =========================================================
# RULE-BASED FALLBACK
# =========================================================

def rule_investigation(alert: dict) -> str:
    severity = alert.get("severity", "LOW")
    event    = alert.get("event", "unknown")
    if severity in ("HIGH", "CRITICAL"):
        return f"High-severity event '{event}' detected — immediate analyst review required."
    if severity == "MEDIUM":
        return f"Suspicious activity '{event}' — monitor for escalation."
    return f"Low-risk event '{event}' — logged for audit trail."

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
    ip    = alert.get("ip") or "unknown"

    if MODEL_AVAILABLE:
        window                 = update_window(ip, alert)
        predicted_attack, conf = predict_next_attack(window)
        summary                = get_context(predicted_attack)

        alert["predicted_next_attack"] = predicted_attack
        alert["confidence"]            = round(conf, 4)
        alert["investigation"]         = (
            f"{summary} "
            f"(LSTM predicted '{predicted_attack}' with {conf * 100:.1f}% confidence "
            f"based on last {len(window)} events from {ip}.)"
        )
        alert["investigation_method"]  = "lstm_sequence_model"

    else:
        alert["investigation"]        = rule_investigation(alert)
        alert["investigation_method"] = "rule_based"

    producer.send("investigated_alerts", alert)
    print(json.dumps(alert, default=str), flush=True)