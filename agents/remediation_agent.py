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

print("Remediation Agent Running...\n")

for message in consumer:

    alert = message.value

    if alert["severity"] == "HIGH":

        print("\n=== AUTOMATED RESPONSE ===")
        print(f"Blocking IP: {alert['ip']}")
        print("Action: Firewall rule simulated")
        print("==========================")