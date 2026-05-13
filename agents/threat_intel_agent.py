from kafka import KafkaConsumer
import json
import os

_bootstrap = os.environ.get(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9094"
)

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
    "privilege_escalation": "T1068 - Exploitation for Privilege Escalation",
    "unauthorized_access": "T1078 - Valid Accounts",
    "dos_hulk": "T1498 - Network Denial of Service",
    "ddos_attempt": "T1498 - Network Denial of Service",
    "botnet_activity": "T1584 - Compromise Infrastructure",
}



print("Threat Intelligence Agent Running...\n")

for message in consumer:

    try:

        alert = message.value

        event = alert.get("event", "unknown")

        technique = MITRE_ATTACK.get(
            event,
            "Unknown Technique"
        )

        alert["mitre_attack"] = technique

        print("\n=== THREAT INTELLIGENCE ===")
        print(json.dumps(alert, indent=2))
        print("===========================\n")

    except Exception as exc:

        print("\nThreat Intel Processing Error")
        print(str(exc))