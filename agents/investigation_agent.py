"""Enrich canonical SOC events through the durable sequence predictor."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from backend.database import init_db, persist_event
from common.events import (
    InvestigationMetadata,
    SOCEvent,
    SequencePredictionCandidate,
    StageName,
    deserialize_event,
)
from ml.sequence_detection.predictor import (
    DEFAULT_STATE_TTL_SECONDS,
    SequencePredictor,
)


SEQUENCE_ARTIFACT_DIR = _repo_root / "ml" / "sequence_detection"
sequence_predictor: SequencePredictor | None = None

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


def create_runtime_predictor() -> SequencePredictor:
    import redis

    redis_host = os.environ.get("REDIS_HOST", "localhost")
    redis_port = int(os.environ.get("REDIS_PORT", 6379))
    ttl_seconds = int(
        os.environ.get("SEQUENCE_STATE_TTL_SECONDS", DEFAULT_STATE_TTL_SECONDS)
    )
    redis_client = redis.Redis(
        host=redis_host,
        port=redis_port,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=5,
    )
    try:
        redis_client.ping()
    except Exception as exc:
        raise ConnectionError(
            f"Redis sequence state is unavailable at {redis_host}:{redis_port}: {exc}"
        ) from exc
    return SequencePredictor.from_artifacts(
        redis_client,
        SEQUENCE_ARTIFACT_DIR,
        ttl_seconds=ttl_seconds,
    )


def process_event(
    event: SOCEvent,
    predictor: SequencePredictor | None = None,
) -> SOCEvent:
    """Delegate sequence inference and preserve the canonical event identity."""

    runtime = predictor or sequence_predictor
    if runtime is None:
        metadata = InvestigationMetadata(
            summary="Sequence predictor is not initialized; no prediction was generated.",
            method="lstm_sequence_model_unavailable",
            model_status="not_initialized",
            sequence_state_backend="redis",
            sequence_state_status="not_initialized",
        )
    else:
        outcome = runtime.predict(event)
        candidates = [
            SequencePredictionCandidate(
                rank=item.rank,
                attack_class=item.attack_class,
                confidence=round(item.confidence, 6),
            )
            for item in outcome.top_predictions
        ]
        if outcome.status == "predicted":
            context = get_context(outcome.predicted_class or "unknown")
            metadata = InvestigationMetadata(
                summary=(
                    f"{context} LSTM predicted '{outcome.predicted_class}' with "
                    f"{(outcome.confidence or 0.0) * 100:.1f}% confidence from "
                    f"{outcome.sequence_length_used} durable events."
                ),
                method="lstm_sequence_model",
                predicted_next_attack=outcome.predicted_class,
                confidence=round(outcome.confidence or 0.0, 6),
                model_status=outcome.model_status,
                top_predictions=candidates,
                sequence_length_used=outcome.sequence_length_used,
                model_version=outcome.model_version,
                prediction_timestamp=outcome.predicted_at,
                sequence_state_backend=outcome.state_backend,
                sequence_state_status=outcome.state_status,
            )
        elif outcome.status == "warming_up":
            metadata = InvestigationMetadata(
                summary=f"{outcome.detail} No prediction was generated.",
                method="lstm_sequence_model_warming_up",
                model_status=outcome.model_status,
                sequence_length_used=outcome.sequence_length_used,
                model_version=outcome.model_version,
                sequence_state_backend=outcome.state_backend,
                sequence_state_status=outcome.state_status,
            )
        else:
            metadata = InvestigationMetadata(
                summary=(
                    "Next-attack prediction unavailable because the trained LSTM "
                    f"model is not loaded. Status: '{outcome.model_status}'. "
                    f"{outcome.detail}"
                ),
                method="lstm_sequence_model_unavailable",
                model_status=outcome.model_status,
                model_version=outcome.model_version,
                sequence_state_backend=outcome.state_backend,
                sequence_state_status=outcome.state_status,
            )

    enriched = event.model_copy(deep=True)
    enriched.investigation_metadata = metadata
    return enriched.advance_stage(StageName.INVESTIGATION, "investigation-agent")


def main() -> None:
    global sequence_predictor

    from common.kafka import (
        consume_forever,
        create_consumer,
        create_producer,
        publish_event,
    )

    init_db()
    sequence_predictor = create_runtime_predictor()
    if sequence_predictor.available:
        print(
            "Investigation sequence predictor ready "
            f"(Redis TTL={sequence_predictor.store.ttl_seconds}s)"
        )
    else:
        print(
            "WARNING: Next-attack prediction unavailable: "
            f"{sequence_predictor.model_status}: "
            f"{sequence_predictor.unavailable_detail}"
        )

    consumer = create_consumer("soc_alerts", "soc-investigation")
    producer = create_producer()
    print("Investigation Agent Running...\n")

    def handle(payload: dict) -> None:
        event = process_event(deserialize_event(payload))
        persist_event(event)
        publish_event(producer, "investigated_alerts", event)
        print(json.dumps(event.to_message(), default=str), flush=True)

    consume_forever(consumer, handle, "investigation-agent")


if __name__ == "__main__":
    main()
