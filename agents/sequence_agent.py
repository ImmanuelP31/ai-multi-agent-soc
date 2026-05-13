from collections import deque
import json
import os
import sys
from pathlib import Path

import numpy as np
import redis

from kafka import KafkaConsumer, KafkaProducer

from tensorflow.keras.models import load_model

# --------------------------------------------------
# FIX PROJECT ROOT
# --------------------------------------------------

_repo_root = Path(__file__).resolve().parents[1]

if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

# --------------------------------------------------
# CONFIG
# --------------------------------------------------

BOOTSTRAP = os.environ.get(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9094"
)

REDIS_HOST = os.environ.get(
    "REDIS_HOST",
    "localhost"
)

REDIS_PORT = int(
    os.environ.get(
        "REDIS_PORT",
        6379
    )
)

SEQUENCE_LENGTH = 5

# --------------------------------------------------
# LOAD MODEL
# --------------------------------------------------

MODEL_PATH = (
    _repo_root /
    "ml" /
    "sequence_detection" /
    "sequence_model.h5"
)

LABEL_MAP_PATH = (
    _repo_root /
    "ml" /
    "sequence_detection" /
    "label_mapping.json"
)

model = load_model(MODEL_PATH)

with open(LABEL_MAP_PATH, "r") as f:
    label_mapping = json.load(f)

reverse_mapping = {
    int(v): k
    for k, v in label_mapping.items()
}

# --------------------------------------------------
# REDIS
# --------------------------------------------------

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True
)

# --------------------------------------------------
# KAFKA
# --------------------------------------------------

consumer = KafkaConsumer(
    "soc_alerts",
    bootstrap_servers=BOOTSTRAP,
    auto_offset_reset="earliest",
    value_deserializer=lambda m:
        json.loads(m.decode("utf-8"))
)

producer = KafkaProducer(
    bootstrap_servers=BOOTSTRAP,
    value_serializer=lambda v:
        json.dumps(v, default=str).encode("utf-8")
)

print("Sequence Agent Running...\n")

# --------------------------------------------------
# ENCODING MAPS
# --------------------------------------------------

severity_encoding = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3
}

# --------------------------------------------------
# EVENT WINDOW
# --------------------------------------------------

event_window = deque(maxlen=SEQUENCE_LENGTH)

# --------------------------------------------------
# EVENT LOOP
# --------------------------------------------------

for message in consumer:

    alert = message.value

    event = alert.get("event", "unknown")

    severity = alert.get(
        "severity",
        "LOW"
    )

    ip_addr = alert.get("ip", "unknown")

    # ----------------------------------------------
    # ENCODE EVENT
    # ----------------------------------------------

    attack_encoded = label_mapping.get(
        event,
        0
    )

    severity_encoded = severity_encoding.get(
        severity,
        0
    )

    # Simulated anomaly score
    anomaly_score = 0.9 \
        if severity == "HIGH" else 0.4

    # Simulated packet rate
    packet_rate = (
        alert.get(
            "failed_login_count",
            1
        ) * 100
    )

    # Attack frequency
    redis_key = f"freq:{ip_addr}"

    attack_frequency = redis_client.incr(
        redis_key
    )

    redis_client.expire(redis_key, 3600)

    # Repeated offender
    repeated_offender = (
        1 if attack_frequency > 3 else 0
    )

    # ----------------------------------------------
    # CREATE FEATURE VECTOR
    # ----------------------------------------------

    feature_vector = [
        attack_encoded,
        severity_encoded,
        anomaly_score,
        packet_rate,
        attack_frequency,
        repeated_offender
    ]

    # ----------------------------------------------
    # ADD TO WINDOW
    # ----------------------------------------------

    event_window.append(feature_vector)

    # Store latest sequence in Redis
    redis_client.set(
        f"sequence:{ip_addr}",
        json.dumps(list(event_window))
    )

    print(f"\nEvent Window: {list(event_window)}")

    # ----------------------------------------------
    # RUN LSTM ONLY WHEN FULL
    # ----------------------------------------------

    if len(event_window) == SEQUENCE_LENGTH:

        sequence_array = np.array(
            [list(event_window)]
        )

        prediction = model.predict(
            sequence_array,
            verbose=0
        )

        predicted_class = int(
            np.argmax(prediction)
        )

        predicted_attack = reverse_mapping.get(
            predicted_class,
            "unknown"
        )

        confidence = float(
            np.max(prediction)
        )

        correlated_alert = {
            "source_ip": ip_addr,
            "sequence": list(event_window),
            "predicted_next_attack":
                predicted_attack,
            "confidence": round(
                confidence,
                4
            ),
            "current_event": event,
            "severity": severity,
            "type": "sequence_correlation"
        }

        # ------------------------------------------
        # PUBLISH TO KAFKA
        # ------------------------------------------

        producer.send(
            "sequence_alerts",
            correlated_alert
        )

        print("\n=== SEQUENCE ALERT ===")
        print(json.dumps(
            correlated_alert,
            indent=2
        ))