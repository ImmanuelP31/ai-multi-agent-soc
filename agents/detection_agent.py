"""Detect anomalies from canonical numeric network-flow telemetry."""

from __future__ import annotations

from collections import defaultdict
import json
import os
from pathlib import Path
import sys

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from backend.database import init_db, persist_event
from common.events import DetectionMetadata, SOCEvent, Severity, StageName, deserialize_event
from common.kafka import consume_forever, create_consumer, create_producer, publish_event
from ml.features.network_flow import (
    DEFAULT_BUNDLE_PATH,
    AnomalyModelBundle,
    InvalidTelemetryError,
    ModelBundleError,
    load_anomaly_bundle,
)


DETECTION_MODE = os.environ.get("DETECTION_MODE", "ml").strip().lower()
ANOMALY_BUNDLE_PATH = Path(
    os.environ.get("ANOMALY_MODEL_BUNDLE", str(DEFAULT_BUNDLE_PATH))
)

FALLBACK_RULE_VERSION = "telemetry-rules-v1"
FALLBACK_RULE_BASIS = (
    "Documented local demo limits for observed packet and byte rates; "
    "not learned model thresholds"
)
FALLBACK_THRESHOLDS = {
    "high_packets_per_second": 100_000.0,
    "high_bytes_per_second": 50_000_000.0,
    "medium_packets_per_second": 10_000.0,
    "medium_bytes_per_second": 5_000_000.0,
}


def load_detection_runtime(
    mode: str = DETECTION_MODE,
    bundle_path: Path = ANOMALY_BUNDLE_PATH,
) -> AnomalyModelBundle | None:
    normalized_mode = mode.strip().lower()
    if normalized_mode == "ml":
        return load_anomaly_bundle(bundle_path)
    if normalized_mode == "rule_based":
        return None
    raise ValueError(
        f"Unsupported DETECTION_MODE '{mode}'. Use 'ml' or 'rule_based'."
    )


def _numeric_telemetry(event: SOCEvent, feature: str) -> float:
    value = event.telemetry.flow_features.get(feature)
    if value is None:
        return 0.0
    if isinstance(value, bool):
        raise InvalidTelemetryError(f"Feature '{feature}' must be numeric")
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise InvalidTelemetryError(f"Feature '{feature}' must be numeric") from exc


def fallback_severity(event: SOCEvent) -> str:
    """Explicit fallback based only on observed telemetry."""

    packets_per_second = _numeric_telemetry(event, "Flow Packets/s")
    bytes_per_second = _numeric_telemetry(event, "Flow Bytes/s")
    if (
        packets_per_second >= FALLBACK_THRESHOLDS["high_packets_per_second"]
        or bytes_per_second >= FALLBACK_THRESHOLDS["high_bytes_per_second"]
    ):
        return "HIGH"
    if (
        packets_per_second >= FALLBACK_THRESHOLDS["medium_packets_per_second"]
        or bytes_per_second >= FALLBACK_THRESHOLDS["medium_bytes_per_second"]
    ):
        return "MEDIUM"
    return "LOW"


failed_login_counter: dict[str, int] = defaultdict(int)
failed_login_results: dict[str, int] = {}


def process_event(
    event: SOCEvent,
    *,
    mode: str,
    bundle: AnomalyModelBundle | None = None,
) -> SOCEvent:
    """Apply detection; ML inputs come only from telemetry.flow_features."""

    normalized_mode = mode.strip().lower()
    if normalized_mode == "ml":
        if bundle is None:
            raise ModelBundleError(
                "ML detection is configured but no validated anomaly bundle is loaded"
            )
        inference = bundle.infer(event.telemetry.flow_features)
        severity = inference.severity
        anomaly_score = round(inference.decision_score, 6)
        detection = DetectionMetadata(
            method="isolation_forest",
            anomaly_score=anomaly_score,
            decision_score=anomaly_score,
            model_available=True,
            model_status="loaded",
            model_version=bundle.metadata.model_version,
            feature_pipeline_version=bundle.metadata.feature_pipeline_version,
            threshold_version=bundle.thresholds.version,
            threshold_basis=bundle.thresholds.basis,
            thresholds={
                "anomaly_decision_threshold": (
                    bundle.thresholds.anomaly_decision_threshold
                ),
                "high_severity_decision_threshold": (
                    bundle.thresholds.high_severity_decision_threshold
                ),
            },
        )
    elif normalized_mode == "rule_based":
        severity = fallback_severity(event)
        detection = DetectionMetadata(
            method="rule_based_fallback",
            anomaly_score=None,
            decision_score=None,
            model_available=False,
            model_status="explicit_fallback",
            model_version=FALLBACK_RULE_VERSION,
            feature_pipeline_version=None,
            threshold_version=FALLBACK_RULE_VERSION,
            threshold_basis=FALLBACK_RULE_BASIS,
            thresholds=FALLBACK_THRESHOLDS,
        )
    else:
        raise ValueError(
            f"Unsupported detection mode '{mode}'. Use 'ml' or 'rule_based'."
        )

    failed_login_count = None
    if event.event == "failed_login" and event.source_ip:
        identity = str(event.event_id)
        if identity not in failed_login_results:
            failed_login_counter[event.source_ip] += 1
            failed_login_results[identity] = failed_login_counter[event.source_ip]
        failed_login_count = failed_login_results[identity]
        if failed_login_count > 5:
            severity = "HIGH"
        detection.failed_login_count = failed_login_count

    enriched = event.model_copy(deep=True)
    enriched.severity = Severity(severity)
    enriched.detection = detection
    enriched.telemetry.failed_login_count = failed_login_count
    return enriched.advance_stage(StageName.DETECTION, "detection-agent")


def main() -> None:
    try:
        bundle = load_detection_runtime()
    except (ModelBundleError, ValueError) as exc:
        raise SystemExit(f"Detection configuration error: {exc}") from exc

    if bundle is None:
        print(
            f"Detection Agent Running in explicit fallback mode "
            f"({FALLBACK_RULE_VERSION})\n"
        )
    else:
        print(
            f"Detection Agent Running with {bundle.metadata.model_version} "
            f"from {ANOMALY_BUNDLE_PATH}\n"
        )

    consumer = create_consumer("soc_logs", "soc-detection")
    producer = create_producer()
    init_db()

    def handle(payload: dict) -> None:
        event = process_event(
            deserialize_event(payload),
            mode=DETECTION_MODE,
            bundle=bundle,
        )
        persist_event(event)
        publish_event(producer, "soc_alerts", event)
        print(json.dumps(event.to_message(), default=str), flush=True)

    consume_forever(consumer, handle, "detection-agent")


if __name__ == "__main__":
    main()
