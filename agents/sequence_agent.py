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
from ml.sequence_detection.pipeline import (
    SEQUENCE_FEATURES,
    SEQUENCE_LENGTH as DEFAULT_SEQUENCE_LENGTH,
    load_preprocessor,
    validate_metadata,
)


REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
SEQUENCE_LENGTH = DEFAULT_SEQUENCE_LENGTH
NUM_FEATURES = len(SEQUENCE_FEATURES)

MODEL_PATH = _repo_root / "ml" / "sequence_detection" / "sequence_model.keras"
LABEL_MAP_PATH = _repo_root / "ml" / "sequence_detection" / "label_mapping.json"
METADATA_PATH = _repo_root / "ml" / "sequence_detection" / "metadata.json"
PREPROCESSOR_PATH = (
    _repo_root / "ml" / "sequence_detection" / "sequence_preprocessor.joblib"
)

model = None
sequence_preprocessor = None
reverse_mapping: dict[int, str] = {}


def load_sequence_assets() -> None:
    global model, sequence_preprocessor, reverse_mapping, SEQUENCE_LENGTH, NUM_FEATURES
    from tensorflow.keras.models import load_model

    with open(METADATA_PATH, encoding="utf-8") as file:
        metadata = json.load(file)
    with open(LABEL_MAP_PATH) as file:
        label_mapping = json.load(file)
    validate_metadata(metadata, label_mapping)
    if metadata.get("status") != "trained":
        raise RuntimeError(
            "Sequence metadata requires retraining; run the generation and "
            "training scripts before starting sequence_agent."
        )
    SEQUENCE_LENGTH = int(metadata["sequence_length"])
    NUM_FEATURES = int(metadata["num_features"])
    sequence_preprocessor = load_preprocessor(PREPROCESSOR_PATH)
    model = load_model(MODEL_PATH)
    expected_shape = (None, SEQUENCE_LENGTH, NUM_FEATURES)
    if model.input_shape != expected_shape:
        raise RuntimeError(
            f"Sequence model expects {model.input_shape}; expected {expected_shape}"
        )
    reverse_mapping = {int(value): key for key, value in label_mapping.items()}


event_windows: dict[str, deque[tuple[str, list[float]]]] = {}


def _feature_vector(event: SOCEvent) -> list[float]:
    if sequence_preprocessor is None:
        raise RuntimeError("Sequence preprocessor is not loaded")
    return sequence_preprocessor.transform_telemetry(
        event.telemetry.flow_features
    )[0].tolist()


def process_event(event: SOCEvent, redis_client) -> SOCEvent | None:
    source = event.source_ip or str(event.incident_id)
    vector = _feature_vector(event)

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
