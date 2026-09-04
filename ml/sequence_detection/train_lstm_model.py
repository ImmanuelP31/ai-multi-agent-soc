"""Train and compare the leakage-free next-event LSTM experiment."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any

import numpy as np
from sklearn.utils.class_weight import compute_class_weight

_repo_root = Path(__file__).resolve().parents[2]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from ml.sequence_detection.pipeline import (
    MarkovBaseline,
    SEQUENCE_FEATURES,
    SEQUENCE_MODEL_VERSION,
    evaluate_probabilities,
    load_dataset_artifact,
    load_preprocessor,
    validate_metadata,
)


THIS_DIR = Path(__file__).resolve().parent
DATASET_PATH = THIS_DIR / "sequence_dataset.npz"
PREPROCESSOR_PATH = THIS_DIR / "sequence_preprocessor.joblib"
METADATA_PATH = THIS_DIR / "metadata.json"
MODEL_PATH = THIS_DIR / "sequence_model.keras"
METRICS_PATH = THIS_DIR / "sequence_evaluation.json"
RANDOM_STATE = 42


def load_training_artifacts() -> tuple[dict[str, np.ndarray], dict[str, Any]]:
    if not METADATA_PATH.is_file():
        raise FileNotFoundError(
            f"Sequence metadata is missing: {METADATA_PATH}. "
            "Run generate_rich_sequences.py first."
        )
    with open(METADATA_PATH, encoding="utf-8") as file:
        metadata = json.load(file)
    with open(THIS_DIR / "label_mapping.json", encoding="utf-8") as file:
        label_mapping = json.load(file)
    validate_metadata(metadata, label_mapping)
    preprocessor = load_preprocessor(PREPROCESSOR_PATH)
    if list(preprocessor.training_groups) != metadata["train_groups"]:
        raise ValueError("Preprocessor provenance does not match metadata train groups")
    return load_dataset_artifact(DATASET_PATH), metadata


def build_model(sequence_length: int, num_features: int, num_classes: int):
    try:
        import tensorflow as tf
        from tensorflow.keras.layers import Dense, Dropout, Input, LSTM
        from tensorflow.keras.models import Sequential
    except ImportError as exc:
        raise RuntimeError(
            "TensorFlow is required to train the LSTM. Install the project "
            "requirements in a supported Python environment."
        ) from exc

    tf.keras.utils.set_random_seed(RANDOM_STATE)
    model = Sequential(
        [
            Input(shape=(sequence_length, num_features)),
            LSTM(128),
            Dropout(0.3),
            Dense(64, activation="relu"),
            Dense(num_classes, activation="softmax"),
        ]
    )
    model.compile(
        optimizer="adam",
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )
    return model


def calculate_class_weights(y_train: np.ndarray) -> dict[int, float]:
    present = np.unique(y_train)
    weights = compute_class_weight(
        class_weight="balanced",
        classes=present,
        y=y_train,
    )
    return {int(label): float(weight) for label, weight in zip(present, weights)}


def train() -> dict[str, Any]:
    arrays, metadata = load_training_artifacts()
    X_train = arrays["X_train"]
    y_train = arrays["y_train"]
    X_validation = arrays["X_validation"]
    y_validation = arrays["y_validation"]
    X_test = arrays["X_test"]
    y_test = arrays["y_test"]

    for split_name, values in (
        ("train", y_train),
        ("validation", y_validation),
        ("test", y_test),
    ):
        if len(values) == 0:
            raise ValueError(
                f"The {split_name} split produced no windows. Use source groups "
                "with at least sequence_length + 1 rows per sequence entity."
            )

    sequence_length = int(metadata["sequence_length"])
    num_classes = int(metadata["num_classes"])
    expected_shape = (sequence_length, len(SEQUENCE_FEATURES))
    if tuple(X_train.shape[1:]) != expected_shape:
        raise ValueError(
            f"Training shape {X_train.shape[1:]} does not match {expected_shape}"
        )

    class_weights = calculate_class_weights(y_train)
    print("Class support (imbalance is retained and reported):")
    for label, support in metadata["class_support"]["train"].items():
        print(f"  {label}: {support:,}")

    model = build_model(sequence_length, len(SEQUENCE_FEATURES), num_classes)
    from tensorflow.keras.callbacks import EarlyStopping

    history = model.fit(
        X_train,
        y_train,
        validation_data=(X_validation, y_validation),
        epochs=30,
        batch_size=128,
        class_weight=class_weights,
        callbacks=[
            EarlyStopping(
                monitor="val_loss",
                patience=4,
                restore_best_weights=True,
            )
        ],
        verbose=1,
    )

    test_probabilities = model.predict(X_test, batch_size=512, verbose=0)
    lstm_metrics = evaluate_probabilities(
        y_test,
        test_probabilities,
        metadata["class_mapping"],
    )
    test_loss = float(model.evaluate(X_test, y_test, verbose=0)[0])
    lstm_metrics["loss"] = test_loss

    baseline = MarkovBaseline.fit(
        arrays["previous_train"],
        y_train,
        num_classes,
    )
    baseline_probabilities = baseline.predict_proba(arrays["previous_test"])
    baseline_metrics = evaluate_probabilities(
        y_test,
        baseline_probabilities,
        metadata["class_mapping"],
    )

    comparison = {
        "lstm": {
            key: lstm_metrics[key]
            for key in ("accuracy", "macro_f1", "weighted_f1", "top_3_accuracy")
        },
        "markov": {
            key: baseline_metrics[key]
            for key in ("accuracy", "macro_f1", "weighted_f1", "top_3_accuracy")
        },
        "lstm_macro_f1_delta": (
            lstm_metrics["macro_f1"] - baseline_metrics["macro_f1"]
        ),
        "lstm_outperforms_markov": (
            lstm_metrics["macro_f1"] > baseline_metrics["macro_f1"]
        ),
    }
    evaluation = {
        "model_version": SEQUENCE_MODEL_VERSION,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "held_out_groups": metadata["test_groups"],
        "lstm": lstm_metrics,
        "markov": baseline_metrics,
        "comparison": comparison,
    }

    model.save(MODEL_PATH)
    with open(METRICS_PATH, "w", encoding="utf-8") as file:
        json.dump(evaluation, file, indent=2)

    metadata.update(
        {
            "status": "trained",
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "model_artifact": MODEL_PATH.name,
            "training": {
                "epochs_completed": len(history.history["loss"]),
                "batch_size": 128,
                "class_weights": {
                    str(label): weight for label, weight in class_weights.items()
                },
                "class_imbalance_strategy": "balanced class weights from y_train only",
            },
            "test_metrics": lstm_metrics,
            "baseline_metrics": baseline_metrics,
            "comparison": comparison,
        }
    )
    validate_metadata(metadata, metadata["class_mapping"])
    with open(METADATA_PATH, "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=2)

    print("\nHeld-out test comparison")
    print(
        "  LSTM   "
        f"accuracy={lstm_metrics['accuracy']:.4f} "
        f"macro_f1={lstm_metrics['macro_f1']:.4f} "
        f"top_3={lstm_metrics['top_3_accuracy']:.4f}"
    )
    print(
        "  Markov "
        f"accuracy={baseline_metrics['accuracy']:.4f} "
        f"macro_f1={baseline_metrics['macro_f1']:.4f} "
        f"top_3={baseline_metrics['top_3_accuracy']:.4f}"
    )
    if comparison["lstm_outperforms_markov"]:
        print("  Result: LSTM improves on the Markov baseline by macro F1.")
    else:
        print("  Result: LSTM does not improve on the Markov baseline by macro F1.")
    print(f"\nModel: {MODEL_PATH}")
    print(f"Metrics: {METRICS_PATH}")
    return evaluation


if __name__ == "__main__":
    train()
