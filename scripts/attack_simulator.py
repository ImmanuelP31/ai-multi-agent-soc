from kafka import KafkaProducer
import json
import os
import random
import time

_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")

producer = KafkaProducer(
    bootstrap_servers=_bootstrap,
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
)

attack_types = [
    "failed_login",
    "port_scan",
    "malware_detected",
    "ddos_attempt",
    "unauthorized_access",
    "privilege_escalation"
]

ips = [
    "192.168.1.10",
    "192.168.1.20",
    "10.0.0.5",
    "172.16.0.3",
    "45.33.12.99"
]

users = [
    "admin",
    "guest",
    "root",
    "test_user"
]

while True:

    attack = {
        "event": random.choice(attack_types),
        "ip": random.choice(ips),
        "user": random.choice(users),
        "timestamp": time.time()
    }

    producer.send("soc_logs", attack)

    print(f"Generated Attack: {attack}")

    time.sleep(2)