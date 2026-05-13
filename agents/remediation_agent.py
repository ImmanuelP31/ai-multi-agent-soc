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
    auto_offset_reset='latest',
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)

print("Remediation Agent Running...\n")

for message in consumer:

    try:

        alert = message.value

        severity = alert.get("severity", "LOW")

        if severity == "HIGH":

            ip_addr = alert.get("ip", "unknown")

            print("\n=== AUTOMATED RESPONSE ===")
            print(f"Blocking IP: {ip_addr}")
            print("Action: Firewall rule simulated")
            print("==========================\n")

    except Exception as exc:

        print("\nRemediation Error")
        print(str(exc))