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

print("Reporting Agent Running...\n")

for message in consumer:

    alert = message.value

    report = f"""
    ===== INCIDENT REPORT =====

    Event: {alert['event']}
    Severity: {alert['severity']}
    IP: {alert['ip']}
    User: {alert.get('user', 'n/a')}

    ===========================
    """

    print(report)