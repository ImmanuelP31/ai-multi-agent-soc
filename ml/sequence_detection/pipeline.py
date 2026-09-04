"""Leakage-free data contract for next-event sequence prediction."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import random
from typing import Any, Iterable, Mapping

import joblib
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler

from ml.features.network_flow import (
    NETWORK_FLOW_FEATURES,
    InvalidTelemetryError,
    canonical_feature_frame,
    telemetry_feature_frame,
)


SEQUENCE_LENGTH = 5
SEQUENCE_FEATURES = NETWORK_FLOW_FEATURES
TARGET_COLUMN = "Label"
SOURCE_GROUP_COLUMN = "_source_group"
ENTITY_COLUMN = "_sequence_entity"
ROW_ORDER_COLUMN = "_row_order"
SEQUENCE_PIPELINE_VERSION = "sequence-telemetry-v2"
PREPROCESSOR_ARTIFACT_VERSION = "sequence-preprocessor-v1"
SEQUENCE_MODEL_VERSION = "lstm-next-event-v2"
DATASET_ARTIFACT_VERSION = "grouped-sequences-v1"

SOURCE_ENTITY_COLUMNS: tuple[str, ...] = (
    "Source IP",
    "Src IP",
    "SourceIP",
    "src_ip",
    "Flow ID",
    "Session ID",
)


class SequenceDataError(ValueError):
    """Raised when source data cannot satisfy the sequence contract."""


class SequenceArtifactError(RuntimeError):
    """Raised when saved sequence artifacts are missing or inconsistent."""


@dataclass(frozen=True)
class GroupSplit:
    train: tuple[str, ...]
    validation: tuple[str, ...]
    test: tuple[str, ...]

    def validate(self) -> None:
        train, validation, test = map(set, (self.train, self.validation, self.test))
        if not train or not validation or not test:
            raise SequenceDataError("Train, validation, and test groups must be non-empty")
        if train & validation or train & test or validation & test:
            raise SequenceDataError("Source groups must be disjoint across splits")


@dataclass
class SequenceBatch:
    X: np.ndarray
    y: np.ndarray
    previous_class: np.ndarray
    source_groups: np.ndarray
    entities: np.ndarray

    def validate(self, sequence_length: int, num_features: int) -> None:
        expected = (len(self.y), sequence_length, num_features)
        if self.X.shape != expected:
            raise SequenceDataError(
                f"Sequence shape {self.X.shape} does not match {expected}"
            )
        for values in (self.previous_class, self.source_groups, self.entities):
            if len(values) != len(self.y):
                raise SequenceDataError("Sequence metadata is not aligned with labels")


@dataclass
class SequenceDataset:
    train: SequenceBatch
    validation: SequenceBatch
    test: SequenceBatch
    split: GroupSplit
    label_mapping: dict[str, int]
    entity_columns: dict[str, str]


@dataclass
class SequencePreprocessor:
    """Train-fitted preprocessing reused by generation and runtime inference."""

    imputer: SimpleImputer
    scaler: StandardScaler
    feature_names: tuple[str, ...]
    training_groups: tuple[str, ...]
    training_rows: int
    artifact_version: str = PREPROCESSOR_ARTIFACT_VERSION
    pipeline_version: str = SEQUENCE_PIPELINE_VERSION

    def validate(self) -> None:
        if self.artifact_version != PREPROCESSOR_ARTIFACT_VERSION:
            raise SequenceArtifactError(
                f"Unsupported preprocessor version: {self.artifact_version}"
            )
        if self.pipeline_version != SEQUENCE_PIPELINE_VERSION:
            raise SequenceArtifactError(
                f"Unsupported sequence pipeline version: {self.pipeline_version}"
            )
        if tuple(self.feature_names) != SEQUENCE_FEATURES:
            raise SequenceArtifactError(
                "Preprocessor feature order does not match the runtime contract"
            )
        expected = len(SEQUENCE_FEATURES)
        for name, component in (("imputer", self.imputer), ("scaler", self.scaler)):
            if getattr(component, "n_features_in_", None) != expected:
                raise SequenceArtifactError(
                    f"Sequence {name} does not expect {expected} features"
                )
        if not self.training_groups or self.training_rows <= 0:
            raise SequenceArtifactError("Preprocessor has no training provenance")

    def transform_frame(self, frame: pd.DataFrame) -> np.ndarray:
        canonical = canonical_feature_frame(frame)
        return self.scaler.transform(self.imputer.transform(canonical)).astype(
            np.float32
        )

    def transform_telemetry(self, telemetry: Mapping[str, Any]) -> np.ndarray:
        return self.transform_frame(telemetry_feature_frame(telemetry))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_label(value: Any) -> str:
    return " ".join(str(value).strip().replace("\ufffd", "-").split())


def prepare_source_frame(
    frame: pd.DataFrame,
    source_group: str,
) -> tuple[pd.DataFrame, str]:
    """Validate one capture and assign a boundary-safe sequence entity."""

    prepared = frame.copy()
    prepared.columns = prepared.columns.str.strip()
    if TARGET_COLUMN not in prepared:
        raise SequenceDataError(f"{source_group} is missing '{TARGET_COLUMN}'")

    canonical = canonical_feature_frame(prepared)
    result = canonical.copy()
    result[TARGET_COLUMN] = prepared[TARGET_COLUMN].map(normalize_label)
    if (result[TARGET_COLUMN] == "").any():
        raise SequenceDataError(f"{source_group} contains an empty target label")

    entity_column = next(
        (name for name in SOURCE_ENTITY_COLUMNS if name in prepared.columns),
        None,
    )
    if entity_column is None:
        entity_values = pd.Series(source_group, index=prepared.index, dtype="object")
        entity_strategy = "source_file"
    else:
        entity_values = prepared[entity_column].astype("string").fillna("missing")
        entity_strategy = entity_column

    result[SOURCE_GROUP_COLUMN] = source_group
    result[ENTITY_COLUMN] = source_group + "::" + entity_values.astype(str)
    result[ROW_ORDER_COLUMN] = np.arange(len(result), dtype=np.int64)
    return result.reset_index(drop=True), entity_strategy


def load_source_frames(
    paths: Iterable[str | Path],
) -> tuple[dict[str, pd.DataFrame], dict[str, str]]:
    frames: dict[str, pd.DataFrame] = {}
    entity_columns: dict[str, str] = {}
    for raw_path in sorted((Path(path) for path in paths), key=lambda path: path.name):
        source_group = raw_path.name
        if source_group in frames:
            raise SequenceDataError(f"Duplicate source filename: {source_group}")
        frame, entity_strategy = prepare_source_frame(
            pd.read_csv(raw_path, low_memory=False),
            source_group,
        )
        frames[source_group] = frame
        entity_columns[source_group] = entity_strategy
    if not frames:
        raise SequenceDataError("No source CSV files were provided")
    return frames, entity_columns


def split_source_groups(
    groups: Iterable[str],
    *,
    random_state: int = 42,
) -> GroupSplit:
    """Split independent source files before any overlapping windows exist."""

    ordered = sorted(set(groups))
    if len(ordered) < 3:
        raise SequenceDataError(
            "At least three independent source files are required for group splits"
        )
    random.Random(random_state).shuffle(ordered)
    test_count = max(1, round(len(ordered) * 0.2))
    validation_count = max(1, round(len(ordered) * 0.2))
    while len(ordered) - test_count - validation_count < 1:
        if test_count >= validation_count and test_count > 1:
            test_count -= 1
        elif validation_count > 1:
            validation_count -= 1
        else:
            raise SequenceDataError("Could not create three non-empty group splits")

    split = GroupSplit(
        train=tuple(sorted(ordered[: -test_count - validation_count])),
        validation=tuple(sorted(ordered[-test_count - validation_count : -test_count])),
        test=tuple(sorted(ordered[-test_count:])),
    )
    split.validate()
    return split


def fit_label_mapping(frames: Iterable[pd.DataFrame]) -> dict[str, int]:
    labels = sorted(
        {
            normalize_label(label)
            for frame in frames
            for label in frame[TARGET_COLUMN].tolist()
        }
    )
    if len(labels) < 2:
        raise SequenceDataError("Sequence training requires at least two classes")
    return {label: index for index, label in enumerate(labels)}


def fit_sequence_preprocessor(
    training_frames: Mapping[str, pd.DataFrame],
) -> SequencePreprocessor:
    if not training_frames:
        raise SequenceDataError("No training frames were provided")
    training = pd.concat(
        [training_frames[group] for group in sorted(training_frames)],
        ignore_index=True,
    )
    canonical = canonical_feature_frame(training)
    empty = [column for column in canonical if canonical[column].notna().sum() == 0]
    if empty:
        raise InvalidTelemetryError(
            f"Training features contain no usable values: {empty}"
        )
    imputer = SimpleImputer(strategy="median")
    imputed = imputer.fit_transform(canonical)
    scaler = StandardScaler()
    scaler.fit(imputed)
    preprocessor = SequencePreprocessor(
        imputer=imputer,
        scaler=scaler,
        feature_names=SEQUENCE_FEATURES,
        training_groups=tuple(sorted(training_frames)),
        training_rows=len(training),
    )
    preprocessor.validate()
    return preprocessor


def build_sequences(
    frames: Mapping[str, pd.DataFrame],
    preprocessor: SequencePreprocessor,
    label_mapping: Mapping[str, int],
    *,
    sequence_length: int = SEQUENCE_LENGTH,
) -> SequenceBatch:
    if sequence_length < 1:
        raise SequenceDataError("Sequence length must be positive")

    sequence_blocks: list[np.ndarray] = []
    target_blocks: list[np.ndarray] = []
    previous_blocks: list[np.ndarray] = []
    source_group_blocks: list[np.ndarray] = []
    entity_blocks: list[np.ndarray] = []

    for source_group in sorted(frames):
        frame = frames[source_group]
        for entity, entity_frame in frame.groupby(ENTITY_COLUMN, sort=False):
            ordered = entity_frame.sort_values(ROW_ORDER_COLUMN, kind="stable")
            features = preprocessor.transform_frame(ordered)
            try:
                encoded = np.array(
                    [label_mapping[label] for label in ordered[TARGET_COLUMN]],
                    dtype=np.int32,
                )
            except KeyError as exc:
                raise SequenceDataError(f"Unknown target label: {exc.args[0]}") from exc

            window_count = len(ordered) - sequence_length
            if window_count <= 0:
                continue
            windows = np.lib.stride_tricks.sliding_window_view(
                features,
                sequence_length,
                axis=0,
            )[:window_count]
            sequence_blocks.append(windows.transpose(0, 2, 1).copy())
            target_blocks.append(encoded[sequence_length:])
            previous_blocks.append(encoded[sequence_length - 1 : -1])
            source_group_blocks.append(np.repeat(source_group, window_count))
            entity_blocks.append(np.repeat(str(entity), window_count))

    if sequence_blocks:
        X = np.concatenate(sequence_blocks).astype(np.float32, copy=False)
        y = np.concatenate(target_blocks).astype(np.int32, copy=False)
        previous_class = np.concatenate(previous_blocks).astype(np.int32, copy=False)
        source_groups = np.concatenate(source_group_blocks).astype(str, copy=False)
        entities = np.concatenate(entity_blocks).astype(str, copy=False)
    else:
        X = np.empty(
            (0, sequence_length, len(SEQUENCE_FEATURES)),
            dtype=np.float32,
        )
        y = np.empty(0, dtype=np.int32)
        previous_class = np.empty(0, dtype=np.int32)
        source_groups = np.empty(0, dtype=str)
        entities = np.empty(0, dtype=str)
    batch = SequenceBatch(
        X=X,
        y=y,
        previous_class=previous_class,
        source_groups=source_groups,
        entities=entities,
    )
    batch.validate(sequence_length, len(SEQUENCE_FEATURES))
    return batch


def prepare_sequence_dataset(
    paths: Iterable[str | Path],
    *,
    random_state: int = 42,
    sequence_length: int = SEQUENCE_LENGTH,
) -> tuple[SequenceDataset, SequencePreprocessor]:
    frames, entity_columns = load_source_frames(paths)
    split = split_source_groups(frames, random_state=random_state)
    label_mapping = fit_label_mapping(frames.values())
    train_frames = {group: frames[group] for group in split.train}
    preprocessor = fit_sequence_preprocessor(train_frames)
    dataset = SequenceDataset(
        train=build_sequences(
            train_frames, preprocessor, label_mapping, sequence_length=sequence_length
        ),
        validation=build_sequences(
            {group: frames[group] for group in split.validation},
            preprocessor,
            label_mapping,
            sequence_length=sequence_length,
        ),
        test=build_sequences(
            {group: frames[group] for group in split.test},
            preprocessor,
            label_mapping,
            sequence_length=sequence_length,
        ),
        split=split,
        label_mapping=label_mapping,
        entity_columns=entity_columns,
    )
    return dataset, preprocessor


def class_support(y: np.ndarray, label_mapping: Mapping[str, int]) -> dict[str, int]:
    counts = np.bincount(y, minlength=len(label_mapping))
    return {
        label: int(counts[index])
        for label, index in sorted(label_mapping.items(), key=lambda item: item[1])
    }


def create_metadata(
    dataset: SequenceDataset,
    preprocessor: SequencePreprocessor,
    *,
    sequence_length: int = SEQUENCE_LENGTH,
    random_state: int = 42,
) -> dict[str, Any]:
    metadata = {
        "status": "prepared",
        "model_version": SEQUENCE_MODEL_VERSION,
        "sequence_pipeline_version": SEQUENCE_PIPELINE_VERSION,
        "dataset_artifact_version": DATASET_ARTIFACT_VERSION,
        "preprocessing_artifact_version": PREPROCESSOR_ARTIFACT_VERSION,
        "created_at": utc_now(),
        "sequence_length": sequence_length,
        "num_features": len(SEQUENCE_FEATURES),
        "feature_columns": list(SEQUENCE_FEATURES),
        "target_column": TARGET_COLUMN,
        "num_classes": len(dataset.label_mapping),
        "class_mapping": dict(dataset.label_mapping),
        "split_strategy": (
            "Source CSV files are split before windows with a seeded 60/20/20 "
            "group split. Windows are then built independently per source/session "
            "entity and never cross a file or entity boundary."
        ),
        "split_random_state": random_state,
        "train_groups": list(dataset.split.train),
        "validation_groups": list(dataset.split.validation),
        "test_groups": list(dataset.split.test),
        "entity_columns": dataset.entity_columns,
        "dataset_sizes": {
            "train_sequences": len(dataset.train.y),
            "validation_sequences": len(dataset.validation.y),
            "test_sequences": len(dataset.test.y),
            "training_preprocessing_rows": preprocessor.training_rows,
        },
        "class_support": {
            "train": class_support(dataset.train.y, dataset.label_mapping),
            "validation": class_support(dataset.validation.y, dataset.label_mapping),
            "test": class_support(dataset.test.y, dataset.label_mapping),
        },
        "preprocessor": {
            "artifact": "sequence_preprocessor.joblib",
            "version": preprocessor.artifact_version,
            "fitted_on_groups": list(preprocessor.training_groups),
            "training_rows": preprocessor.training_rows,
        },
        "model_artifact": "sequence_model.keras",
        "test_metrics": None,
        "baseline_metrics": None,
    }
    validate_metadata(metadata, dataset.label_mapping)
    return metadata


def validate_metadata(
    metadata: Mapping[str, Any],
    label_mapping: Mapping[str, int] | None = None,
) -> None:
    if metadata.get("sequence_pipeline_version") != SEQUENCE_PIPELINE_VERSION:
        raise SequenceArtifactError("Sequence pipeline version is incompatible")
    if metadata.get("model_version") != SEQUENCE_MODEL_VERSION:
        raise SequenceArtifactError("Sequence model version is incompatible")
    if tuple(metadata.get("feature_columns", ())) != SEQUENCE_FEATURES:
        raise SequenceArtifactError("Metadata feature order is incompatible")
    if metadata.get("num_features") != len(SEQUENCE_FEATURES):
        raise SequenceArtifactError("Metadata feature count is inconsistent")
    if int(metadata.get("sequence_length", 0)) < 1:
        raise SequenceArtifactError("Metadata sequence length is invalid")
    mapping = dict(label_mapping or metadata.get("class_mapping") or {})
    expected_indexes = list(range(len(mapping)))
    if sorted(mapping.values()) != expected_indexes:
        raise SequenceArtifactError("Class mapping indexes must be contiguous")
    if metadata.get("num_classes") != len(mapping):
        raise SequenceArtifactError("Metadata class count is inconsistent")
    recorded_mapping = metadata.get("class_mapping")
    if recorded_mapping is not None and dict(recorded_mapping) != mapping:
        raise SequenceArtifactError("Metadata and label mapping disagree")


def save_preprocessor(preprocessor: SequencePreprocessor, path: str | Path) -> Path:
    destination = Path(path)
    preprocessor.validate()
    joblib.dump(preprocessor, destination)
    return destination


def load_preprocessor(path: str | Path) -> SequencePreprocessor:
    source = Path(path)
    if not source.is_file():
        raise SequenceArtifactError(f"Sequence preprocessor is missing: {source}")
    try:
        preprocessor = joblib.load(source)
    except Exception as exc:
        raise SequenceArtifactError(
            f"Could not load sequence preprocessor {source}: {exc}"
        ) from exc
    if not isinstance(preprocessor, SequencePreprocessor):
        raise SequenceArtifactError("Invalid sequence preprocessor artifact type")
    preprocessor.validate()
    return preprocessor


def save_dataset_artifacts(
    dataset: SequenceDataset,
    preprocessor: SequencePreprocessor,
    output_dir: str | Path,
    *,
    random_state: int = 42,
    sequence_length: int = SEQUENCE_LENGTH,
) -> dict[str, Any]:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    arrays: dict[str, np.ndarray] = {}
    for split_name, batch in (
        ("train", dataset.train),
        ("validation", dataset.validation),
        ("test", dataset.test),
    ):
        arrays[f"X_{split_name}"] = batch.X
        arrays[f"y_{split_name}"] = batch.y
        arrays[f"previous_{split_name}"] = batch.previous_class
        arrays[f"groups_{split_name}"] = batch.source_groups
        arrays[f"entities_{split_name}"] = batch.entities
    np.savez_compressed(destination / "sequence_dataset.npz", **arrays)
    save_preprocessor(preprocessor, destination / "sequence_preprocessor.joblib")

    metadata = create_metadata(
        dataset,
        preprocessor,
        sequence_length=sequence_length,
        random_state=random_state,
    )
    with open(destination / "label_mapping.json", "w", encoding="utf-8") as file:
        json.dump(dataset.label_mapping, file, indent=2, sort_keys=True)
    with open(destination / "metadata.json", "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=2)
    return metadata


def load_dataset_artifact(path: str | Path) -> dict[str, np.ndarray]:
    source = Path(path)
    if not source.is_file():
        raise SequenceArtifactError(
            f"Grouped sequence dataset is missing: {source}. "
            "Run generate_rich_sequences.py first."
        )
    with np.load(source) as data:
        return {name: data[name] for name in data.files}


def top_k_accuracy(y_true: np.ndarray, probabilities: np.ndarray, k: int = 3) -> float:
    if len(y_true) == 0:
        return 0.0
    width = min(k, probabilities.shape[1])
    top = np.argpartition(probabilities, -width, axis=1)[:, -width:]
    return float(np.mean(np.any(top == y_true[:, None], axis=1)))


def evaluate_probabilities(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    label_mapping: Mapping[str, int],
) -> dict[str, Any]:
    num_classes = len(label_mapping)
    if probabilities.shape != (len(y_true), num_classes):
        raise SequenceDataError(
            "Prediction probability shape does not match labels/class mapping"
        )
    labels = list(range(num_classes))
    names = [
        name for name, _ in sorted(label_mapping.items(), key=lambda item: item[1])
    ]
    predicted = np.argmax(probabilities, axis=1)
    report = classification_report(
        y_true,
        predicted,
        labels=labels,
        target_names=names,
        output_dict=True,
        zero_division=0,
    )
    per_class = {
        name: {
            "precision": float(report[name]["precision"]),
            "recall": float(report[name]["recall"]),
            "f1": float(report[name]["f1-score"]),
            "support": int(report[name]["support"]),
        }
        for name in names
    }
    return {
        "accuracy": float(accuracy_score(y_true, predicted)),
        "macro_f1": float(report["macro avg"]["f1-score"]),
        "weighted_f1": float(report["weighted avg"]["f1-score"]),
        "top_3_accuracy": top_k_accuracy(y_true, probabilities, 3),
        "per_class": per_class,
        "support": {name: values["support"] for name, values in per_class.items()},
        "total_support": int(len(y_true)),
        "confusion_matrix": confusion_matrix(
            y_true, predicted, labels=labels
        ).tolist(),
    }


@dataclass
class MarkovBaseline:
    transition_counts: np.ndarray
    class_counts: np.ndarray

    @classmethod
    def fit(
        cls,
        previous_class: np.ndarray,
        targets: np.ndarray,
        num_classes: int,
    ) -> "MarkovBaseline":
        transitions = np.zeros((num_classes, num_classes), dtype=np.float64)
        class_counts = np.zeros(num_classes, dtype=np.float64)
        for previous, target in zip(previous_class, targets):
            transitions[int(previous), int(target)] += 1.0
            class_counts[int(target)] += 1.0
        if class_counts.sum() == 0:
            raise SequenceDataError("Cannot fit Markov baseline without training windows")
        return cls(transitions, class_counts)

    def predict_proba(self, previous_class: np.ndarray) -> np.ndarray:
        probabilities = np.empty(
            (len(previous_class), len(self.class_counts)), dtype=np.float64
        )
        prior = self.class_counts / self.class_counts.sum()
        for row, previous in enumerate(previous_class):
            counts = self.transition_counts[int(previous)]
            probabilities[row] = counts / counts.sum() if counts.sum() else prior
        return probabilities
