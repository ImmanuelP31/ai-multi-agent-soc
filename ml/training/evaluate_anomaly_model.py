"""Evaluate the saved anomaly bundle without fitting on test data."""

from __future__ import annotations

import json
from pathlib import Path
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

_repo_root = Path(__file__).resolve().parents[2]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from ml.features.network_flow import DEFAULT_BUNDLE_PATH, load_anomaly_bundle


TEST_DATASET = _repo_root / "ml" / "datasets" / "test_dataset.parquet"
EVALUATION_PATH = _repo_root / "ml" / "models" / "anomaly_evaluation.json"


def _safe_rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def evaluate_anomaly_model(
    dataset_path: Path = TEST_DATASET,
    bundle_path: Path = DEFAULT_BUNDLE_PATH,
    output_path: Path = EVALUATION_PATH,
) -> dict:
    print(f"Loading test dataset: {dataset_path}")
    dataframe = pd.read_parquet(dataset_path)
    dataframe.columns = dataframe.columns.str.strip()
    if "Label" not in dataframe:
        raise ValueError("Test dataset is missing the Label column")

    bundle = load_anomaly_bundle(bundle_path)
    transformed = bundle.transform_frame(dataframe)
    decision_scores = bundle.model.decision_function(transformed)
    y_true = (dataframe["Label"] != 0).astype(int).to_numpy()
    y_pred = np.where(
        decision_scores < bundle.thresholds.anomaly_decision_threshold,
        1,
        0,
    )

    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    precision = float(precision_score(y_true, y_pred, zero_division=0))
    recall = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    false_positive_rate = _safe_rate(fp, fp + tn)
    false_negative_rate = _safe_rate(fn, fn + tp)
    detection_rate = _safe_rate(tp, tp + fn)

    metrics = {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": matrix.tolist(),
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "true_positives": tp,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "detection_rate": detection_rate,
        "thresholds": {
            "version": bundle.thresholds.version,
            "anomaly_decision_threshold": (
                bundle.thresholds.anomaly_decision_threshold
            ),
            "high_severity_decision_threshold": (
                bundle.thresholds.high_severity_decision_threshold
            ),
            "basis": bundle.thresholds.basis,
        },
        "model_metadata": {
            "bundle_version": bundle.metadata.bundle_version,
            "model_version": bundle.metadata.model_version,
            "feature_pipeline_version": bundle.metadata.feature_pipeline_version,
            "trained_at": bundle.metadata.trained_at,
            "sklearn_version": bundle.metadata.sklearn_version,
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(metrics, indent=2))
    print(json.dumps(metrics, indent=2))
    print(f"Saved evaluation metrics: {output_path}")
    return metrics


if __name__ == "__main__":
    evaluate_anomaly_model()
