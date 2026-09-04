"""Build leakage-free, group-separated LSTM sequence artifacts."""

from __future__ import annotations

from pathlib import Path
import sys

_repo_root = Path(__file__).resolve().parents[2]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from ml.sequence_detection.pipeline import (
    SEQUENCE_FEATURES,
    SEQUENCE_LENGTH,
    prepare_sequence_dataset,
    save_dataset_artifacts,
)


THIS_DIR = Path(__file__).resolve().parent
DATASET_DIR = THIS_DIR.parent / "datasets"


def main() -> None:
    csv_files = sorted(DATASET_DIR.glob("*.csv"))
    if len(csv_files) < 3:
        raise FileNotFoundError(
            f"At least three independent CICIDS CSV files are required in "
            f"{DATASET_DIR}; found {len(csv_files)}. Group-level train, "
            "validation, and test splits cannot be built otherwise."
        )

    print("Loading source captures:")
    for path in csv_files:
        print(f"  {path.name}")

    dataset, preprocessor = prepare_sequence_dataset(csv_files)
    metadata = save_dataset_artifacts(dataset, preprocessor, THIS_DIR)

    print("\nLeakage-safe sequence dataset created")
    print(f"  Features: {len(SEQUENCE_FEATURES)} telemetry fields")
    print(f"  Sequence length: {SEQUENCE_LENGTH}")
    print(f"  Train groups: {metadata['train_groups']}")
    print(f"  Validation groups: {metadata['validation_groups']}")
    print(f"  Test groups: {metadata['test_groups']}")
    print(f"  Sequence counts: {metadata['dataset_sizes']}")
    print(f"  Preprocessor fitted rows: {preprocessor.training_rows:,}")
    print(f"\nArtifacts saved in {THIS_DIR}")
    print("  sequence_dataset.npz")
    print("  sequence_preprocessor.joblib")
    print("  label_mapping.json")
    print("  metadata.json")


if __name__ == "__main__":
    main()
