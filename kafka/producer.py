from kafka import KafkaProducer
import json
import os
import time

# From the host (venv): Docker maps EXTERNAL listener to localhost:9094 (see docker-compose.yml).
# Override if needed: set KAFKA_BOOTSTRAP_SERVERS=kafka:9092 when running inside Compose.
_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")

producer = KafkaProducer(
    bootstrap_servers=_bootstrap,
    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
)

logs = [
    {"event": "failed_login", "ip": "192.168.1.10"},
    {"event": "port_scan", "ip": "192.168.1.20"},
    {"event": "malware_detected", "ip": "192.168.1.30"}
]

while True:
    for log in logs:
        producer.send('soc_logs', log)
        print(f"Sent: {log}")
        time.sleep(2)