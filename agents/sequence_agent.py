"""Optional sequence-correlation worker using the canonical event contract."""

from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
import sys

import numpy as np
import redis

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from common.events import InvestigationMetadata, SOCEvent, StageName, deserialize_event
from common.kafka import consume_forever, create_consumer, create_producer, publish_event


REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
SEQUENCE_LENGTH = 5

MODEL_PATH = _repo_root / "ml" / "sequence_detection" / "sequence_model.h5"
LABEL_MAP_PATH = _repo_root / "ml" / "sequence_detection" / "label_mapping.json"

model = None
reverse_mapping: dict[int, str] = {}


def load_sequence_assets() -> None:
    global model, reverse_mapping
    from tensorflow.keras.models import load_model

    model = load_model(MODEL_PATH)
    with open(LABEL_MAP_PATH) as file:
        label_mapping = json.load(file)
    reverse_mapping = {int(value): key for key, value in label_mapping.items()}


severity_encoding = {
    "UNKNOWN": 0,
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}
event_windows: dict[str, deque[tuple[str, list[float]]]] = {}


def _feature_vector(
    event: SOCEvent,
    attack_frequency: int,
    repeated_offender: bool,
) -> list[float]:
    label_mapping = {name: index for index, name in reverse_mapping.items()}
    packet_rate = (
        event.telemetry.packet_rate
        or (event.telemetry.failed_login_count or 1) * 100
    )
    anomaly_score = event.detection.anomaly_score
    if anomaly_score is None:
        anomaly_score = 0.9 if event.severity.value == "HIGH" else 0.4
    return [
        float(label_mapping.get(event.event, 0)),
        float(severity_encoding.get(event.severity.value, 0)),
        float(anomaly_score),
        float(packet_rate),
        float(attack_frequency),
        float(repeated_offender),
    ]


def _frequency_for_event(redis_client, event: SOCEvent) -> int:
    result_key = f"sequence-frequency-result:{event.event_id}"
    source = event.source_ip or str(event.incident_id)
    frequency_key = f"freq:{source}"
    script = """
    local previous = redis.call('GET', KEYS[1])
    if previous then
        return tonumber(previous)
    end
    local frequency = redis.call('INCR', KEYS[2])
    redis.call('EXPIRE', KEYS[2], ARGV[1])
    redis.call('SETEX', KEYS[1], ARGV[1], frequency)
    return frequency
    """
    return int(redis_client.eval(script, 2, result_key, frequency_key, 3600))


def process_event(event: SOCEvent, redis_client) -> SOCEvent | None:
    source = event.source_ip or str(event.incident_id)
    attack_frequency = _frequency_for_event(redis_client, event)
    repeated_offender = attack_frequency > 3
    vector = _feature_vector(event, attack_frequency, repeated_offender)

    if source not in event_windows:
        event_windows[source] = deque(maxlen=SEQUENCE_LENGTH)
    window = event_windows[source]
    identity = str(event.event_id)
    if not any(event_id == identity for event_id, _ in window):
        window.append((identity, vector))

    sequence = [item for _, item in window]
    redis_client.set(f"sequence:{source}", json.dumps(sequence))
    if len(sequence) < SEQUENCE_LENGTH:
        return None

    sequence_array = np.array([sequence])
    prediction = model.predict(sequence_array, verbose=0)
    predicted_class = int(np.argmax(prediction))
    predicted_attack = reverse_mapping.get(predicted_class, "unknown")
    confidence = float(np.max(prediction))

    enriched = event.model_copy(deep=True)
    enriched.telemetry.attack_frequency = attack_frequency
    enriched.telemetry.repeated_ip = repeated_offender
    enriched.telemetry.extra["sequence"] = sequence
    enriched.telemetry.extra["type"] = "sequence_correlation"
    enriched.investigation_metadata = InvestigationMetadata(
        summary=(
            f"Sequence correlation predicted '{predicted_attack}' from "
            f"{SEQUENCE_LENGTH} events for {source}."
        ),
        method="lstm_sequence_model",
        predicted_next_attack=predicted_attack,
        confidence=round(confidence, 4),
        model_status="loaded",
    )
    return enriched.advance_stage(StageName.INVESTIGATION, "sequence-agent")


def main() -> None:
    load_sequence_assets()
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True,
    )
    consumer = create_consumer("soc_alerts", "soc-sequence")
    producer = create_producer()
    print("Sequence Agent Running...\n")

    def handle(payload: dict) -> None:
        result = process_event(deserialize_event(payload), redis_client)
        if result is not None:
            publish_event(producer, "sequence_alerts", result)
            print(json.dumps(result.to_message(), default=str), flush=True)

    consume_forever(consumer, handle, "sequence-agent")


if __name__ == "__main__":
    main()
