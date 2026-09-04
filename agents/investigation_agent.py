"""Enrich canonical SOC events with trained LSTM sequence predictions."""

from __future__ import annotations

from collections import deque
import json
from pathlib import Path
import sys

import numpy as np

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from backend.database import init_db, persist_event
from common.events import (
    InvestigationMetadata,
    SOCEvent,
    StageName,
    deserialize_event,
)
from common.kafka import consume_forever, create_consumer, create_producer, publish_event
from ml.sequence_detection.pipeline import (
    SEQUENCE_FEATURES,
    SEQUENCE_LENGTH as DEFAULT_SEQUENCE_LENGTH,
    load_preprocessor,
    validate_metadata,
)


_seq_dir = _repo_root / "ml" / "sequence_detection"
MODEL_AVAILABLE = False
MODEL_STATUS = "not_loaded"
MODEL_ERROR_MESSAGE = ""
lstm_model = None
sequence_preprocessor = None
LABEL_MAPPING: dict[int, str] = {}
SEQUENCE_LENGTH = DEFAULT_SEQUENCE_LENGTH
NUM_FEATURES = len(SEQUENCE_FEATURES)

_meta_path = _seq_dir / "metadata.json"
if _meta_path.exists():
    with open(_meta_path) as file:
        metadata = json.load(file)
    SEQUENCE_LENGTH = metadata.get("sequence_length", DEFAULT_SEQUENCE_LENGTH)
    NUM_FEATURES = metadata.get("num_features", len(SEQUENCE_FEATURES))
else:
    metadata = {}
    print("metadata.json not found; using sequence defaults")

_label_path = _seq_dir / "label_mapping.json"
if _label_path.exists():
    with open(_label_path) as file:
        raw_mapping = json.load(file)
    LABEL_MAPPING = {int(value): key for key, value in raw_mapping.items()}
else:
    print("label_mapping.json not found; predictions will use class indexes")

_model_path = _seq_dir / "sequence_model.keras"
_preprocessor_path = _seq_dir / "sequence_preprocessor.joblib"
if metadata.get("status") != "trained":
    MODEL_STATUS = "requires_retraining"
    MODEL_ERROR_MESSAGE = (
        "The leakage-free sequence model has not been trained. Expected "
        f"artifacts: {_model_path} and {_preprocessor_path}. Run "
        "ml/sequence_detection/generate_rich_sequences.py followed by "
        "ml/sequence_detection/train_lstm_model.py, or add compatible "
        "artifacts manually, then restart the investigation agent."
    )
elif _model_path.exists() and _preprocessor_path.exists():
    try:
        from tensorflow.keras.models import load_model  # type: ignore

        validate_metadata(metadata, {name: index for index, name in LABEL_MAPPING.items()})
        sequence_preprocessor = load_preprocessor(_preprocessor_path)
        lstm_model = load_model(str(_model_path))
        actual_shape = lstm_model.input_shape
        expected_shape = (None, SEQUENCE_LENGTH, NUM_FEATURES)
        if actual_shape != expected_shape:
            MODEL_STATUS = "shape_mismatch"
            MODEL_ERROR_MESSAGE = (
                f"Sequence model expects {actual_shape}; metadata expects "
                f"{expected_shape}. Replace {_model_path}."
            )
        else:
            MODEL_AVAILABLE = True
            MODEL_STATUS = "loaded"
            print("LSTM sequence model loaded successfully\n")
    except Exception as exc:
        MODEL_STATUS = "load_error"
        MODEL_ERROR_MESSAGE = f"Could not load {_model_path}: {exc}"
else:
    MODEL_STATUS = "missing_model_artifacts"
    missing = [
        str(path)
        for path in (_model_path, _preprocessor_path)
        if not path.exists()
    ]
    MODEL_ERROR_MESSAGE = (
        f"Trained sequence artifacts are missing: {', '.join(missing)}. Add "
        "compatible artifacts manually or run the sequence generation and "
        "training scripts, then restart the investigation agent."
    )

if not MODEL_AVAILABLE:
    print(f"WARNING: {MODEL_ERROR_MESSAGE}\n")


ATTACK_CONTEXT = {
    "BENIGN": "No malicious pattern detected in the recent sequence.",
    "DDoS": "DDoS pattern predicted; initiate traffic rate limiting.",
    "PortScan": "Port scanning predicted; reconnaissance may be in progress.",
    "Bot": "Bot activity predicted; the host may be part of a botnet.",
    "Infiltration": "Infiltration predicted; lateral movement may be underway.",
    "Web Attack - Brute Force": "Brute force predicted; consider account lockout.",
    "Web Attack - XSS": "XSS predicted; review web application firewall rules.",
    "Web Attack - Sql Injection": "SQL injection predicted; database integrity is at risk.",
    "FTP-Patator": "FTP brute force predicted; restrict FTP and rotate credentials.",
    "SSH-Patator": "SSH brute force predicted; require key-based authentication.",
    "DoS slowloris": "Slowloris predicted; tune connection timeouts.",
    "DoS Slowhttptest": "Slow HTTP DoS predicted; review request timeouts.",
    "DoS Hulk": "Hulk DoS predicted; a high-volume flood may be imminent.",
    "DoS GoldenEye": "GoldenEye DoS predicted; an application flood is likely.",
    "Heartbleed": "Heartbleed predicted; patch OpenSSL immediately.",
}


def get_context(attack_name: str) -> str:
    if attack_name in ATTACK_CONTEXT:
        return ATTACK_CONTEXT[attack_name]
    for key, message in ATTACK_CONTEXT.items():
        if key.lower() in attack_name.lower():
            return message
    return f"Unknown predicted attack '{attack_name}'; manual review is required."


ip_windows: dict[str, deque[tuple[str, list[float]]]] = {}


def get_feature_vector(event: SOCEvent) -> list[float]:
    if sequence_preprocessor is None:
        raise RuntimeError("Sequence preprocessor is not loaded")
    transformed = sequence_preprocessor.transform_telemetry(
        event.telemetry.flow_features
    )
    return transformed[0].tolist()


def update_window(event: SOCEvent) -> list[list[float]]:
    source = event.source_ip or str(event.incident_id)
    if source not in ip_windows:
        ip_windows[source] = deque(maxlen=SEQUENCE_LENGTH)
    window = ip_windows[source]
    event_id = str(event.event_id)
    if not any(existing_id == event_id for existing_id, _ in window):
        window.append((event_id, get_feature_vector(event)))
    return [vector for _, vector in window]


def predict_next_attack(window: list[list[float]]) -> tuple[str, float]:
    if len(window) != SEQUENCE_LENGTH:
        raise ValueError(f"Expected {SEQUENCE_LENGTH} events, received {len(window)}")
    values = np.array(window, dtype=np.float32).reshape(
        1, SEQUENCE_LENGTH, NUM_FEATURES
    )
    probabilities = lstm_model.predict(values, verbose=0)[0]
    index = int(np.argmax(probabilities))
    return LABEL_MAPPING.get(index, f"class_{index}"), float(probabilities[index])


def process_event(event: SOCEvent) -> SOCEvent:
    """Apply sequence investigation while preserving canonical identity."""

    source = event.source_ip or str(event.incident_id)
    if MODEL_AVAILABLE:
        window = update_window(event)
        if len(window) == SEQUENCE_LENGTH:
            predicted_attack, confidence = predict_next_attack(window)
            context = get_context(predicted_attack)
            metadata = InvestigationMetadata(
                summary=(
                    f"{context} LSTM predicted '{predicted_attack}' with "
                    f"{confidence * 100:.1f}% confidence from the last "
                    f"{len(window)} events for {source}."
                ),
                method="lstm_sequence_model",
                predicted_next_attack=predicted_attack,
                confidence=round(confidence, 4),
                model_status=MODEL_STATUS,
            )
        else:
            metadata = InvestigationMetadata(
                summary=(
                    f"Collecting telemetry history for {source}: {len(window)}/"
                    f"{SEQUENCE_LENGTH} events. No prediction was generated."
                ),
                method="lstm_sequence_model_warming_up",
                predicted_next_attack=None,
                confidence=None,
                model_status="warming_up",
            )
    else:
        metadata = InvestigationMetadata(
            summary=(
                "Next-attack prediction unavailable because the trained LSTM "
                f"model is not loaded. Status: '{MODEL_STATUS}'. "
                f"{MODEL_ERROR_MESSAGE}"
            ),
            method="lstm_sequence_model_unavailable",
            predicted_next_attack=None,
            confidence=None,
            model_status=MODEL_STATUS,
        )

    enriched = event.model_copy(deep=True)
    enriched.investigation_metadata = metadata
    return enriched.advance_stage(StageName.INVESTIGATION, "investigation-agent")


def main() -> None:
    consumer = create_consumer("soc_alerts", "soc-investigation")
    producer = create_producer()
    init_db()
    print("Investigation Agent Running...\n")

    def handle(payload: dict) -> None:
        event = process_event(deserialize_event(payload))
        persist_event(event)
        publish_event(producer, "investigated_alerts", event)
        print(json.dumps(event.to_message(), default=str), flush=True)

    consume_forever(consumer, handle, "investigation-agent")


if __name__ == "__main__":
    main()
