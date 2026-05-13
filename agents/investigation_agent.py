from kafka import KafkaConsumer, KafkaProducer
import json
import os

_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")

consumer = KafkaConsumer(
    'soc_alerts',
    bootstrap_servers=_bootstrap,
    auto_offset_reset='earliest',
    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
)

producer = KafkaProducer(
    bootstrap_servers=_bootstrap,
    value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
)

print("Investigation Agent Running...\n")

for message in consumer:

    alert = message.value

    if alert["severity"] == "HIGH":
        alert["investigation"] = "Potential active attack detected"

    elif alert["severity"] == "MEDIUM":
        alert["investigation"] = "Suspicious activity requires monitoring"

    else:
        alert["investigation"] = "Low risk activity"

    producer.send("investigated_alerts", alert)

    print(f"Investigated Alert: {alert}")