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

print("Reporting Agent Running...\n")

for message in consumer:

    try:

        alert = message.value

        report = f"""
================ INCIDENT REPORT ================

Event: {alert.get('event', 'unknown')}
Severity: {alert.get('severity', 'unknown')}
IP: {alert.get('ip', 'n/a')}
User: {alert.get('user', 'n/a')}

Investigation:
{alert.get('investigation', 'No investigation data')}

MITRE Technique:
{alert.get('mitre_attack', 'Unknown')}

=================================================
"""

        print(report)

    except Exception as exc:

        print("\nReporting Error")
        print(str(exc))