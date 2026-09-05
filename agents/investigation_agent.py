"""Enrich canonical SOC events through the durable sequence predictor."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from common.events import (
    InvestigationMetadata,
    SOCEvent,
    SequencePredictionCandidate,
    StageName,
)
from common.labels import normalize_attack_label
from ml.sequence_detection.predictor import (
    DEFAULT_STATE_TTL_SECONDS,
    SequencePredictor,
)


SEQUENCE_ARTIFACT_DIR = Path(
    os.environ.get(
        "SEQUENCE_ARTIFACT_DIR",
        str(_repo_root / "ml" / "sequence_detection"),
    )
)
SEQUENCE_PREDICTION_MODE = os.environ.get(
    "SEQUENCE_PREDICTION_MODE",
    "optional",
).strip().lower()

ATTACK_CONTEXT = {
    "BENIGN": "No malicious pattern detected in the recent sequence.",
    "DDoS": "DDoS pattern predicted; initiate traffic rate limiting.",
    "PortScan": "Port scanning predicted; reconnaissance may be in progress.",
    "Bot": "Bot activity predicted; the host may be part of a botnet.",
    "Infiltration": "Infiltration predicted; lateral movement may be underway.",
    "Web Attack - Brute Force": "Brute force predicted; consider account lockout.",
    "Web Attack - XSS": "XSS predicted; review web application firewall rules.",
    "Web Attack - SQL Injection": "SQL injection predicted; database integrity is at risk.",
    "FTP-Patator": "FTP brute force predicted; restrict FTP and rotate credentials.",
    "SSH-Patator": "SSH brute force predicted; require key-based authentication.",
    "DoS slowloris": "Slowloris predicted; tune connection timeouts.",
    "DoS Slowhttptest": "Slow HTTP DoS predicted; review request timeouts.",
    "DoS Hulk": "Hulk DoS predicted; a high-volume flood may be imminent.",
    "DoS GoldenEye": "GoldenEye DoS predicted; an application flood is likely.",
    "Heartbleed": "Heartbleed predicted; patch OpenSSL immediately.",
}


def get_context(attack_name: str) -> str:
    normalized = normalize_attack_label(attack_name)
    if normalized in ATTACK_CONTEXT:
        return ATTACK_CONTEXT[normalized]
    for key, message in ATTACK_CONTEXT.items():
        if key.lower() in normalized.lower():
            return message
    return f"Unknown predicted attack '{normalized}'; manual review is required."


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


def validate_sequence_runtime(
    predictor: SequencePredictor,
    mode: str = SEQUENCE_PREDICTION_MODE,
) -> None:
    normalized_mode = mode.strip().lower()
    if normalized_mode not in {"required", "optional"}:
        raise ValueError(
            "Unsupported SEQUENCE_PREDICTION_MODE "
            f"'{mode}'. Use 'required' or 'optional'."
        )
    if normalized_mode == "required" and not predictor.available:
        raise RuntimeError(
            "LSTM sequence prediction is required but the model is unavailable: "
            f"{predictor.model_status}: {predictor.unavailable_detail}"
        )


class InvestigationProcessor:
    """Enrich one event using an injected sequence predictor."""

    def __init__(self, predictor: SequencePredictor | None) -> None:
        self.predictor = predictor

    def process(self, event: SOCEvent) -> SOCEvent:
        if self.predictor is None:
            metadata = InvestigationMetadata(
                summary=(
                    "Sequence predictor is not initialized; no prediction was "
                    "generated."
                ),
                method="lstm_sequence_model_unavailable",
                model_status="not_initialized",
                sequence_state_backend="redis",
                sequence_state_status="not_initialized",
            )
        else:
            outcome = self.predictor.predict(event)
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
        return enriched.advance_stage(
            StageName.INVESTIGATION,
            "investigation-agent",
        )


def process_event(
    event: SOCEvent,
    predictor: SequencePredictor | None = None,
) -> SOCEvent:
    """Compatibility wrapper for deterministic investigation processing."""

    return InvestigationProcessor(predictor).process(event)


def main() -> None:
    from backend.database import init_db, persist_event
    from common.health import start_health_server
    from common.kafka import (
        consume_forever,
        create_consumer,
        create_producer,
        publish_event,
    )
    from common.pipeline import run_stage

    health = start_health_server("investigation-agent")
    init_db()
    predictor = create_runtime_predictor()
    try:
        validate_sequence_runtime(predictor)
    except (RuntimeError, ValueError) as exc:
        health.set_not_ready("sequence_configuration_error", error=str(exc))
        raise SystemExit(f"Investigation configuration error: {exc}") from exc
    processor = InvestigationProcessor(predictor)
    if predictor.available:
        print(
            "Investigation sequence predictor ready "
            f"(Redis TTL={predictor.store.ttl_seconds}s)"
        )
    else:
        print(
            "WARNING: Next-attack prediction unavailable: "
            f"{predictor.model_status}: "
            f"{predictor.unavailable_detail}"
        )

    consumer = create_consumer("soc_alerts", "soc-investigation")
    producer = create_producer()
    health.set_ready(
        sequence_prediction_mode=SEQUENCE_PREDICTION_MODE,
        model_available=predictor.available,
        model_status=predictor.model_status,
        model_version=predictor.model_version,
        state_backend="redis",
    )
    print("Investigation Agent Running...\n")

    def handle(payload: dict) -> None:
        event = run_stage(
            payload,
            processor,
            persist_event,
            publish=lambda value: publish_event(
                producer,
                "investigated_alerts",
                value,
            ),
        )
        print(json.dumps(event.to_message(), default=str), flush=True)

    consume_forever(consumer, handle, "investigation-agent")


if __name__ == "__main__":
    main()
