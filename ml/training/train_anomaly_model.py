"""Train and save the complete Isolation Forest inference bundle."""

from __future__ import annotations

from pathlib import Path
import sys

import pandas as pd

_repo_root = Path(__file__).resolve().parents[2]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from ml.features.network_flow import (
    DEFAULT_BUNDLE_PATH,
    fit_anomaly_bundle,
    save_anomaly_bundle,
)


TRAIN_DATASET = _repo_root / "ml" / "datasets" / "train_dataset.parquet"


def train_anomaly_model(
    dataset_path: Path = TRAIN_DATASET,
    bundle_path: Path = DEFAULT_BUNDLE_PATH,
):
    print(f"Loading training dataset: {dataset_path}")
    dataframe = pd.read_parquet(dataset_path)
    dataframe.columns = dataframe.columns.str.strip()
    if "Label" not in dataframe:
        raise ValueError("Training dataset is missing the Label column")

    benign = dataframe[dataframe["Label"] == 0].copy()
    if benign.empty:
        raise ValueError("Training split contains no benign rows (Label == 0)")
    print(f"Fitting preprocessing and Isolation Forest on {len(benign)} benign rows")

    bundle = fit_anomaly_bundle(benign)
    saved_path = save_anomaly_bundle(bundle, bundle_path)
    print(f"Saved complete anomaly bundle: {saved_path}")
    print(f"Features: {list(bundle.feature_names)}")
    print(
        "Decision thresholds: "
        f"anomaly={bundle.thresholds.anomaly_decision_threshold:.6f}, "
        f"high={bundle.thresholds.high_severity_decision_threshold:.6f}"
    )
    print(bundle.thresholds.basis)
    return bundle


if __name__ == "__main__":
    train_anomaly_model()
