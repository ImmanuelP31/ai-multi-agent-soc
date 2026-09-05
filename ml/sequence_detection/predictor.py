"""Durable runtime inference for the leakage-free sequence model."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Callable, Mapping

import numpy as np

from common.events import SOCEvent
from common.labels import normalize_attack_label
from ml.sequence_detection.pipeline import (
    SEQUENCE_FEATURES,
    SEQUENCE_LENGTH,
    SequencePreprocessor,
    load_preprocessor,
    validate_metadata,
)


LOGGER = logging.getLogger(__name__)
DEFAULT_STATE_TTL_SECONDS = 3600
DEFAULT_TOP_K = 3
STATE_KEY_PREFIX = "soc:sequence:"

APPEND_SEQUENCE_SCRIPT = """
local items = redis.call('LRANGE', KEYS[1], 0, -1)
for _, raw_item in ipairs(items) do
    local ok, item = pcall(cjson.decode, raw_item)
    if not ok or type(item) ~= 'table' or item['event_id'] == nil
        or item['features'] == nil then
        return redis.error_reply('corrupt sequence state')
    end
    if item['event_id'] == ARGV[1] then
        redis.call('EXPIRE', KEYS[1], tonumber(ARGV[4]))
        return redis.call('LRANGE', KEYS[1], 0, -1)
    end
end
redis.call('RPUSH', KEYS[1], ARGV[2])
redis.call('LTRIM', KEYS[1], -tonumber(ARGV[3]), -1)
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[4]))
return redis.call('LRANGE', KEYS[1], 0, -1)
"""


class SequenceStateError(RuntimeError):
    """Base error for durable sequence state failures."""


class SequenceStateUnavailable(SequenceStateError):
    """Raised when Redis cannot safely read or update a sequence window."""


class SequenceStateCorrupt(SequenceStateError):
    """Raised when existing Redis state cannot be decoded safely."""


@dataclass(frozen=True)
class PredictionCandidate:
    rank: int
    attack_class: str
    confidence: float


@dataclass(frozen=True)
class SequencePrediction:
    status: str
    model_status: str
    detail: str
    predicted_class: str | None = None
    confidence: float | None = None
    top_predictions: tuple[PredictionCandidate, ...] = ()
    sequence_length_used: int = 0
    model_version: str | None = None
    predicted_at: datetime | None = None
    state_backend: str = "redis"
    state_status: str = "not_used"


class RedisSequenceStore:
    """Store one bounded, replay-safe telemetry window per source identity."""

    def __init__(
        self,
        redis_client: Any,
        *,
        sequence_length: int,
        ttl_seconds: int = DEFAULT_STATE_TTL_SECONDS,
        key_prefix: str = STATE_KEY_PREFIX,
        feature_count: int = len(SEQUENCE_FEATURES),
    ) -> None:
        if sequence_length < 1:
            raise ValueError("sequence_length must be positive")
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be positive")
        self.redis_client = redis_client
        self.sequence_length = sequence_length
        self.ttl_seconds = ttl_seconds
        self.key_prefix = key_prefix
        self.feature_count = feature_count

    def key_for(self, source_identity: str) -> str:
        if not source_identity:
            raise ValueError("source_identity must not be empty")
        return f"{self.key_prefix}{source_identity}"

    def _decode_items(
        self,
        key: str,
        raw_items: list[str | bytes],
    ) -> list[dict[str, Any]]:
        decoded: list[dict[str, Any]] = []
        for raw_item in raw_items:
            try:
                if isinstance(raw_item, bytes):
                    raw_item = raw_item.decode("utf-8")
                item = json.loads(raw_item)
                if not isinstance(item.get("event_id"), str):
                    raise ValueError("event_id is missing")
                features = item.get("features")
                if not isinstance(features, list):
                    raise ValueError("features are missing")
                numeric = [float(value) for value in features]
                if len(numeric) != self.feature_count:
                    raise ValueError(
                        f"expected {self.feature_count} features, found {len(numeric)}"
                    )
                if not np.isfinite(numeric).all():
                    raise ValueError("features contain non-finite values")
                item["features"] = numeric
                decoded.append(item)
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                LOGGER.error("Corrupt sequence state at Redis key %s: %s", key, exc)
                raise SequenceStateCorrupt(
                    f"Corrupt sequence state at Redis key {key}: {exc}"
                ) from exc
        return decoded

    def append(
        self,
        source_identity: str,
        event_id: str,
        feature_vector: list[float],
    ) -> list[list[float]]:
        """Append once, trim, refresh TTL, and return the durable window."""

        key = self.key_for(source_identity)
        if len(feature_vector) != self.feature_count:
            raise ValueError(
                f"Expected {self.feature_count} features, found {len(feature_vector)}"
            )
        if not np.isfinite(feature_vector).all():
            raise ValueError("feature_vector contains non-finite values")
        item_json = json.dumps(
            {"event_id": event_id, "features": feature_vector},
            separators=(",", ":"),
        )

        try:
            current_raw = self.redis_client.eval(
                APPEND_SEQUENCE_SCRIPT,
                1,
                key,
                event_id,
                item_json,
                self.sequence_length,
                self.ttl_seconds,
            )
        except Exception as exc:
            if "corrupt sequence state" in str(exc).lower():
                LOGGER.error("Corrupt sequence state at Redis key %s: %s", key, exc)
                raise SequenceStateCorrupt(
                    f"Corrupt sequence state at Redis key {key}: {exc}"
                ) from exc
            LOGGER.error("Redis sequence update failed for %s: %s", key, exc)
            raise SequenceStateUnavailable(
                f"Redis sequence update failed for {key}: {exc}"
            ) from exc

        current = self._decode_items(key, current_raw)
        if len(current) > self.sequence_length:
            raise SequenceStateCorrupt(
                f"Redis sequence at {key} exceeds {self.sequence_length} items"
            )
        return [item["features"] for item in current]


class SequencePredictor:
    """Apply the saved Step 3 preprocessing/model contract to Redis windows."""

    def __init__(
        self,
        *,
        store: RedisSequenceStore,
        model: Any | None,
        preprocessor: SequencePreprocessor | None,
        label_mapping: Mapping[int, str],
        sequence_length: int,
        model_version: str | None,
        model_status: str,
        unavailable_detail: str = "",
        top_k: int = DEFAULT_TOP_K,
    ) -> None:
        if sequence_length != store.sequence_length:
            raise ValueError("Predictor and Redis store sequence lengths must match")
        if top_k < 1:
            raise ValueError("top_k must be positive")
        if (model is None) != (preprocessor is None):
            raise ValueError("Model and preprocessor must be available together")
        if model is not None and not label_mapping:
            raise ValueError("An available model requires a label mapping")
        self.store = store
        self.model = model
        self.preprocessor = preprocessor
        self.label_mapping = dict(label_mapping)
        self.sequence_length = sequence_length
        self.model_version = model_version
        self.model_status = model_status
        self.unavailable_detail = unavailable_detail
        self.top_k = top_k

    @property
    def available(self) -> bool:
        return self.model is not None and self.preprocessor is not None

    @classmethod
    def from_artifacts(
        cls,
        redis_client: Any,
        artifact_dir: str | Path,
        *,
        ttl_seconds: int = DEFAULT_STATE_TTL_SECONDS,
        top_k: int = DEFAULT_TOP_K,
        model_loader: Callable[[str], Any] | None = None,
    ) -> "SequencePredictor":
        directory = Path(artifact_dir)
        metadata_path = directory / "metadata.json"
        label_path = directory / "label_mapping.json"
        default_length = SEQUENCE_LENGTH

        try:
            with open(metadata_path, encoding="utf-8") as file:
                metadata = json.load(file)
            with open(label_path, encoding="utf-8") as file:
                raw_mapping = json.load(file)
            validate_metadata(metadata, raw_mapping)
            sequence_length = int(metadata["sequence_length"])
            store = RedisSequenceStore(
                redis_client,
                sequence_length=sequence_length,
                ttl_seconds=ttl_seconds,
            )
            if metadata.get("status") != "trained":
                detail = (
                    "The leakage-free sequence model requires retraining. Run "
                    "generate_rich_sequences.py and train_lstm_model.py, or add "
                    "the complete compatible artifact set manually."
                )
                return cls(
                    store=store,
                    model=None,
                    preprocessor=None,
                    label_mapping={},
                    sequence_length=sequence_length,
                    model_version=metadata.get("model_version"),
                    model_status="requires_retraining",
                    unavailable_detail=detail,
                    top_k=top_k,
                )

            model_path = directory / str(metadata["model_artifact"])
            preprocessor_path = directory / str(metadata["preprocessor"]["artifact"])
            missing = [
                str(path)
                for path in (model_path, preprocessor_path)
                if not path.is_file()
            ]
            if missing:
                return cls(
                    store=store,
                    model=None,
                    preprocessor=None,
                    label_mapping={},
                    sequence_length=sequence_length,
                    model_version=metadata.get("model_version"),
                    model_status="missing_model_artifacts",
                    unavailable_detail=f"Missing sequence artifacts: {', '.join(missing)}",
                    top_k=top_k,
                )

            preprocessor = load_preprocessor(preprocessor_path)
            if model_loader is None:
                from tensorflow.keras.models import load_model

                model_loader = load_model
            model = model_loader(str(model_path))
            expected_input = (None, sequence_length, len(SEQUENCE_FEATURES))
            if tuple(model.input_shape) != expected_input:
                raise ValueError(
                    f"Model input shape {model.input_shape} does not match "
                    f"{expected_input}"
                )
            if int(model.output_shape[-1]) != len(raw_mapping):
                raise ValueError(
                    "Model output classes do not match the saved label mapping"
                )
            return cls(
                store=store,
                model=model,
                preprocessor=preprocessor,
                label_mapping={
                    int(index): normalize_attack_label(label)
                    for label, index in raw_mapping.items()
                },
                sequence_length=sequence_length,
                model_version=metadata.get("model_version"),
                model_status="loaded",
                top_k=top_k,
            )
        except Exception as exc:
            LOGGER.error("Sequence model loading failed: %s", exc)
            store = RedisSequenceStore(
                redis_client,
                sequence_length=default_length,
                ttl_seconds=ttl_seconds,
            )
            return cls(
                store=store,
                model=None,
                preprocessor=None,
                label_mapping={},
                sequence_length=default_length,
                model_version=None,
                model_status="load_error",
                unavailable_detail=str(exc),
                top_k=top_k,
            )

    def predict(self, event: SOCEvent) -> SequencePrediction:
        if not self.available:
            return SequencePrediction(
                status="unavailable",
                model_status=self.model_status,
                detail=self.unavailable_detail,
                model_version=self.model_version,
            )

        feature_vector = self.preprocessor.transform_telemetry(
            event.telemetry.flow_features
        )[0].tolist()
        source_identity = event.source_ip or str(event.incident_id)
        window = self.store.append(
            source_identity,
            str(event.event_id),
            feature_vector,
        )
        if len(window) < self.sequence_length:
            return SequencePrediction(
                status="warming_up",
                model_status="loaded",
                detail=(
                    f"Collecting telemetry history for {source_identity}: "
                    f"{len(window)}/{self.sequence_length} events."
                ),
                sequence_length_used=len(window),
                model_version=self.model_version,
                state_status="loaded",
            )

        values = np.asarray([window], dtype=np.float32)
        probabilities = np.asarray(self.model.predict(values, verbose=0))[0]
        if probabilities.shape != (len(self.label_mapping),):
            raise ValueError("Sequence model returned an incompatible probability vector")
        if not np.isfinite(probabilities).all():
            raise ValueError("Sequence model returned non-finite probabilities")
        if np.any(probabilities < 0.0) or np.any(probabilities > 1.0):
            raise ValueError("Sequence model returned values outside probability bounds")

        top_count = min(self.top_k, len(probabilities))
        top_indexes = np.argsort(probabilities)[::-1][:top_count]
        top_predictions = tuple(
            PredictionCandidate(
                rank=rank,
                attack_class=normalize_attack_label(self.label_mapping[int(index)]),
                confidence=float(probabilities[index]),
            )
            for rank, index in enumerate(top_indexes, start=1)
        )
        primary = top_predictions[0]
        return SequencePrediction(
            status="predicted",
            model_status="loaded",
            detail="Prediction generated from the durable Redis sequence window.",
            predicted_class=primary.attack_class,
            confidence=primary.confidence,
            top_predictions=top_predictions,
            sequence_length_used=len(window),
            model_version=self.model_version,
            predicted_at=datetime.now(timezone.utc),
            state_status="loaded",
        )
