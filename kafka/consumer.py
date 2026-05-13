from kafka import KafkaConsumer
import json
import os

_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")

consumer = KafkaConsumer(
    'soc_logs',
    bootstrap_servers=_bootstrap,
    auto_offset_reset='earliest',
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)

print("Listening for SOC logs...")

for message in consumer:
    print(f"Received: {message.value}")