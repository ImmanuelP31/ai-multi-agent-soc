"""Detect anomalous SOC events and publish canonical alerts."""

from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import sys

import joblib
import numpy as np

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from backend.database import init_db, persist_event
from common.events import DetectionMetadata, SOCEvent, Severity, StageName, deserialize_event
from common.kafka import consume_forever, create_consumer, create_producer, publish_event


_model_dir = _repo_root / "ml" / "models"
try:
    anomaly_model = joblib.load(_model_dir / "anomaly_model.pkl")
    anomaly_scaler = joblib.load(_model_dir / "anomaly_scaler.pkl")
    anomaly_features = joblib.load(_model_dir / "anomaly_features.pkl")
    print("Isolation Forest model loaded successfully\n")
    MODEL_AVAILABLE = True
except FileNotFoundError:
    print("Trained anomaly model not found; using rule-based detection.\n")
    MODEL_AVAILABLE = False


EVENT_FLOW_FEATURES = {
    "malware_detected": [5000, 50, 200, 900000, 50, 1200, 800, 5, 40, 900],
    "privilege_escalation": [3000, 30, 150, 700000, 40, 1000, 600, 4, 35, 800],
    "unauthorized_access": [4000, 40, 180, 850000, 45, 1100, 700, 5, 38, 850],
    "port_scan": [1000, 200, 10, 500000, 80, 100, 50, 2, 10, 120],
    "ddos_attempt": [8000, 500, 50, 999999, 99, 200, 100, 8, 60, 300],
    "failed_login": [500, 10, 5, 100000, 20, 400, 300, 1, 15, 380],
    "unknown": [200, 5, 3, 50000, 10, 300, 200, 0, 10, 280],
}

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


def extract_features(event: SOCEvent) -> np.ndarray:
    defaults = EVENT_FLOW_FEATURES.get(event.event, EVENT_FLOW_FEATURES["unknown"])
    values = [
        float(event.telemetry.flow_features.get(name, defaults[index]))
        for index, name in enumerate(FEATURE_ORDER)
    ]
    return np.array(values).reshape(1, -1)


def ml_severity(event: SOCEvent) -> tuple[str, float]:
    features = extract_features(event)
    scaled = anomaly_scaler.transform(features)
    prediction = anomaly_model.predict(scaled)[0]
    anomaly_score = float(anomaly_model.score_samples(scaled)[0])

    if prediction == -1:
        return ("HIGH" if anomaly_score < -0.15 else "MEDIUM"), anomaly_score
    return "LOW", anomaly_score


HIGH_SEVERITY = {"malware_detected", "privilege_escalation", "unauthorized_access"}
MEDIUM_SEVERITY = {"port_scan", "ddos_attempt"}


def rule_severity(event: str) -> str:
    if event in HIGH_SEVERITY:
        return "HIGH"
    if event in MEDIUM_SEVERITY:
        return "MEDIUM"
    return "LOW"


failed_login_counter: dict[str, int] = defaultdict(int)
failed_login_results: dict[str, int] = {}


def process_event(event: SOCEvent) -> SOCEvent:
    """Apply detection while preserving canonical identity."""

    if MODEL_AVAILABLE:
        severity, anomaly_score = ml_severity(event)
        detection_method = "isolation_forest"
    else:
        severity = rule_severity(event.event)
        anomaly_score = None
        detection_method = "rule_based"

    failed_login_count = None
    if event.event == "failed_login" and event.source_ip:
        identity = str(event.event_id)
        if identity not in failed_login_results:
            failed_login_counter[event.source_ip] += 1
            failed_login_results[identity] = failed_login_counter[event.source_ip]
        failed_login_count = failed_login_results[identity]
        if failed_login_count > 5:
            severity = "HIGH"

    enriched = event.model_copy(deep=True)
    enriched.severity = Severity(severity)
    enriched.detection = DetectionMetadata(
        method=detection_method,
        anomaly_score=round(anomaly_score, 4) if anomaly_score is not None else None,
        model_available=MODEL_AVAILABLE,
        failed_login_count=failed_login_count,
    )
    enriched.telemetry.failed_login_count = failed_login_count
    return enriched.advance_stage(StageName.DETECTION, "detection-agent")


def main() -> None:
    consumer = create_consumer("soc_logs", "soc-detection")
    producer = create_producer()
    init_db()
    print("Detection Agent Running...\n")

    def handle(payload: dict) -> None:
        event = process_event(deserialize_event(payload))
        persist_event(event)
        publish_event(producer, "soc_alerts", event)
        print(json.dumps(event.to_message(), default=str), flush=True)

    consume_forever(consumer, handle, "detection-agent")


if __name__ == "__main__":
    main()
