"""Single source of truth for anomaly-model network-flow features."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler


FEATURE_PIPELINE_VERSION = "network-flow-v1"
MODEL_BUNDLE_VERSION = "anomaly-bundle-v1"
MODEL_VERSION = "isolation-forest-v1"
DEFAULT_BUNDLE_PATH = Path(__file__).resolve().parents[1] / "models" / "anomaly_bundle.joblib"

NETWORK_FLOW_FEATURES: tuple[str, ...] = (
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "SYN Flag Count",
    "ACK Flag Count",
    "Average Packet Size",
)


class InvalidTelemetryError(ValueError):
    """Raised when telemetry cannot be represented as numeric flow features."""


class ModelBundleError(RuntimeError):
    """Raised when an anomaly bundle is missing, incompatible, or malformed."""


@dataclass(frozen=True)
class AnomalyThresholds:
    version: str
    anomaly_decision_threshold: float
    high_severity_decision_threshold: float
    high_severity_quantile: float
    basis: str

    def validate(self) -> None:
        if self.high_severity_decision_threshold > self.anomaly_decision_threshold:
            raise ModelBundleError(
                "HIGH threshold must be at or below the anomaly threshold"
            )


@dataclass(frozen=True)
class AnomalyModelMetadata:
    bundle_version: str
    model_version: str
    feature_pipeline_version: str
    trained_at: str
    sklearn_version: str
    training_rows: int
    contamination: float
    random_state: int
    training_population: str


@dataclass(frozen=True)
class AnomalyInference:
    decision_score: float
    is_anomaly: bool
    severity: str


@dataclass
class AnomalyModelBundle:
    model: IsolationForest
    imputer: SimpleImputer
    scaler: StandardScaler
    feature_names: tuple[str, ...]
    thresholds: AnomalyThresholds
    metadata: AnomalyModelMetadata

    def validate(self) -> None:
        if self.metadata.bundle_version != MODEL_BUNDLE_VERSION:
            raise ModelBundleError(
                f"Unsupported bundle version: {self.metadata.bundle_version}"
            )
        if self.metadata.model_version != MODEL_VERSION:
            raise ModelBundleError(
                f"Unsupported anomaly model version: {self.metadata.model_version}"
            )
        if self.metadata.feature_pipeline_version != FEATURE_PIPELINE_VERSION:
            raise ModelBundleError(
                "Bundle feature-pipeline version does not match runtime"
            )
        if tuple(self.feature_names) != NETWORK_FLOW_FEATURES:
            raise ModelBundleError(
                "Bundle feature names/order do not match the runtime feature contract"
            )
        if self.metadata.sklearn_version != sklearn.__version__:
            raise ModelBundleError(
                "Bundle scikit-learn version "
                f"{self.metadata.sklearn_version} does not match runtime "
                f"{sklearn.__version__}; retrain the bundle in this environment"
            )
        expected_count = len(NETWORK_FLOW_FEATURES)
        for component_name, component in (
            ("imputer", self.imputer),
            ("scaler", self.scaler),
            ("model", self.model),
        ):
            feature_count = getattr(component, "n_features_in_", None)
            if feature_count != expected_count:
                raise ModelBundleError(
                    f"Bundle {component_name} expects {feature_count} features; "
                    f"runtime requires {expected_count}"
                )
        self.thresholds.validate()

    def transform_frame(self, frame: pd.DataFrame) -> np.ndarray:
        canonical = canonical_feature_frame(frame)
        imputed = self.imputer.transform(canonical)
        return self.scaler.transform(imputed)

    def transform_telemetry(self, telemetry: Mapping[str, Any]) -> np.ndarray:
        return self.transform_frame(telemetry_feature_frame(telemetry))

    def infer(self, telemetry: Mapping[str, Any]) -> AnomalyInference:
        transformed = self.transform_telemetry(telemetry)
        decision_score = float(self.model.decision_function(transformed)[0])
        is_anomaly = (
            decision_score < self.thresholds.anomaly_decision_threshold
        )
        if decision_score < self.thresholds.high_severity_decision_threshold:
            severity = "HIGH"
        elif is_anomaly:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        return AnomalyInference(
            decision_score=decision_score,
            is_anomaly=is_anomaly,
            severity=severity,
        )


def canonical_feature_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Validate, order, and normalize raw feature columns before fitting/transform."""

    normalized = frame.copy()
    normalized.columns = normalized.columns.str.strip()
    missing_columns = [
        feature for feature in NETWORK_FLOW_FEATURES if feature not in normalized
    ]
    if missing_columns:
        raise InvalidTelemetryError(
            f"Missing network-flow feature columns: {missing_columns}"
        )

    selected = normalized.loc[:, list(NETWORK_FLOW_FEATURES)].copy()
    for feature in NETWORK_FLOW_FEATURES:
        try:
            selected[feature] = pd.to_numeric(selected[feature], errors="raise")
        except (TypeError, ValueError) as exc:
            raise InvalidTelemetryError(
                f"Feature '{feature}' contains a non-numeric value"
            ) from exc
    return selected.replace([np.inf, -np.inf], np.nan)


def telemetry_feature_frame(telemetry: Mapping[str, Any]) -> pd.DataFrame:
    """Create one ordered runtime row; absent/None values are imputed by the bundle."""

    row: dict[str, float] = {}
    for feature in NETWORK_FLOW_FEATURES:
        value = telemetry.get(feature)
        if value is None:
            row[feature] = np.nan
            continue
        if isinstance(value, bool):
            raise InvalidTelemetryError(f"Feature '{feature}' must be numeric")
        try:
            row[feature] = float(value)
        except (TypeError, ValueError) as exc:
            raise InvalidTelemetryError(
                f"Feature '{feature}' must be numeric"
            ) from exc
    return canonical_feature_frame(pd.DataFrame([row]))


def fit_anomaly_bundle(
    training_frame: pd.DataFrame,
    *,
    contamination: float = 0.02,
    random_state: int = 42,
    high_severity_quantile: float = 0.005,
) -> AnomalyModelBundle:
    """Fit all preprocessing and model state using benign training rows only."""

    canonical = canonical_feature_frame(training_frame)
    empty_features = [
        feature for feature in NETWORK_FLOW_FEATURES
        if canonical[feature].notna().sum() == 0
    ]
    if empty_features:
        raise InvalidTelemetryError(
            f"Training features contain no usable values: {empty_features}"
        )

    imputer = SimpleImputer(strategy="median")
    imputed = imputer.fit_transform(canonical)
    scaler = StandardScaler()
    transformed = scaler.fit_transform(imputed)
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(transformed)

    decision_scores = model.decision_function(transformed)
    high_threshold = float(
        np.quantile(decision_scores, high_severity_quantile)
    )
    thresholds = AnomalyThresholds(
        version="decision-function-thresholds-v1",
        anomaly_decision_threshold=0.0,
        high_severity_decision_threshold=min(high_threshold, 0.0),
        high_severity_quantile=high_severity_quantile,
        basis=(
            "IsolationForest decision_function boundary (0.0); HIGH is the "
            f"{high_severity_quantile:.3%} lower tail of benign training scores"
        ),
    )
    metadata = AnomalyModelMetadata(
        bundle_version=MODEL_BUNDLE_VERSION,
        model_version=MODEL_VERSION,
        feature_pipeline_version=FEATURE_PIPELINE_VERSION,
        trained_at=datetime.now(timezone.utc).isoformat(),
        sklearn_version=sklearn.__version__,
        training_rows=len(canonical),
        contamination=contamination,
        random_state=random_state,
        training_population="Label == 0 (benign training split only)",
    )
    bundle = AnomalyModelBundle(
        model=model,
        imputer=imputer,
        scaler=scaler,
        feature_names=NETWORK_FLOW_FEATURES,
        thresholds=thresholds,
        metadata=metadata,
    )
    bundle.validate()
    return bundle


def save_anomaly_bundle(
    bundle: AnomalyModelBundle,
    path: str | Path = DEFAULT_BUNDLE_PATH,
) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    bundle.validate()
    joblib.dump(bundle, destination)
    return destination


def load_anomaly_bundle(
    path: str | Path = DEFAULT_BUNDLE_PATH,
) -> AnomalyModelBundle:
    source = Path(path)
    if not source.is_file():
        raise ModelBundleError(
            f"Anomaly model bundle is missing: {source}. "
            "Run ml/training/train_anomaly_model.py first."
        )
    try:
        bundle = joblib.load(source)
    except Exception as exc:
        raise ModelBundleError(
            f"Could not load anomaly model bundle {source}: {exc}"
        ) from exc
    if not isinstance(bundle, AnomalyModelBundle):
        raise ModelBundleError(
            f"Invalid anomaly model bundle type: {type(bundle).__name__}"
        )
    bundle.validate()
    return bundle
