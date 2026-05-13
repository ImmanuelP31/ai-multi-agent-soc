from kafka import KafkaConsumer
import json
import os

_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")

consumer = KafkaConsumer(
    'investigated_alerts',
    bootstrap_servers=_bootstrap,
    auto_offset_reset='earliest',
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)

MITRE_ATTACK = {
    "failed_login": "T1110 - Brute Force",
    "port_scan": "T1046 - Network Service Discovery",
    "malware_detected": "T1204 - User Execution",
    "privilege_escalation": "T1068 - Exploitation for Privilege Escalation"
}

print("Threat Intelligence Agent Running...\n")

for message in consumer:

    alert = message.value

    technique = MITRE_ATTACK.get(
        alert["event"],
        "Unknown Technique"
    )

    alert["mitre_attack"] = technique

    print(f"Threat Intelligence: {alert}")