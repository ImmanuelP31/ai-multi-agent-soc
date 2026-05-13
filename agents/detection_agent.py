from collections import defaultdict
import json
import os
import sys
from pathlib import Path

# Running `python agents/detection_agent.py` puts `agents/` on sys.path, not the repo root.
_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from kafka import KafkaConsumer, KafkaProducer

from backend.database import init_db, persist_alert

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

HIGH_SEVERITY = [
    "malware_detected",
    "privilege_escalation",
    "unauthorized_access"
]

MEDIUM_SEVERITY = [
    "port_scan",
    "ddos_attempt"
]

LOW_SEVERITY = [
    "failed_login"
]

for message in consumer:

    log = message.value

    event = log.get("event", "unknown")

    if event in HIGH_SEVERITY:
        severity = "HIGH"

    elif event in MEDIUM_SEVERITY:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    ip_addr = log.get("ip")

    if event == "failed_login":
        if ip_addr:
            failed_login_counter[ip_addr] += 1
            if failed_login_counter[ip_addr] > 5:
                severity = "HIGH"

    alert = {
        "event": event,
        "severity": severity,
        "ip": ip_addr,
        "user": log.get("user"),
    }

    if event == "failed_login" and ip_addr is not None:
        alert["failed_login_count"] = failed_login_counter[ip_addr]

    if "timestamp" in log:
        alert["timestamp"] = log["timestamp"]

    try:
        producer.send("soc_alerts", alert).get(timeout=15)
    except Exception as exc:
        print(
            json.dumps({"kafka_error": str(exc), "alert": alert}),
            file=sys.stderr,
            flush=True,
        )

    # One JSON object per line — dashboards, logs, offline analysis.
    print(json.dumps(alert, default=str), flush=True)

    try:
        persist_alert(alert)
    except Exception as exc:
        print(
            json.dumps({"storage_error": str(exc), "alert": alert}),
            file=sys.stderr,
            flush=True,
        )

import requests

requests.post(
    "http://localhost:8000/push-alert",
    json=alert
)

