"""Build leakage-free, group-separated LSTM sequence artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

_repo_root = Path(__file__).resolve().parents[2]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from ml.sequence_detection.pipeline import (
    DEFAULT_SESSION_GAP_SECONDS,
    SEQUENCE_FEATURES,
    SEQUENCE_LENGTH,
    prepare_sequence_dataset,
    save_dataset_artifacts,
)


THIS_DIR = Path(__file__).resolve().parent
DATASET_DIR = THIS_DIR.parent / "datasets"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build class-covered train/validation/test sequence artifacts from "
            "rich CICIDS flow exports."
        )
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=DATASET_DIR,
        help="Directory containing rich CICIDS CSV flow exports",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=THIS_DIR,
        help="Directory in which generated sequence artifacts are written",
    )
    parser.add_argument(
        "--session-gap-seconds",
        type=int,
        default=DEFAULT_SESSION_GAP_SECONDS,
        help="Start a new source session after this inactivity gap",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Seed used by the whole-session split search",
    )
    return parser.parse_args(argv)


def _print_class_support(metadata: dict) -> None:
    support = metadata["class_support"]
    labels = metadata["class_mapping"]
    label_width = max(len("Class"), *(len(label) for label in labels))
    print("\nClass coverage (sequence targets)")
    print(f"  {'Class':<{label_width}}  {'Train':>10}  {'Val':>10}  {'Test':>10}")
    for label in labels:
        print(
            f"  {label:<{label_width}}  {support['train'][label]:>10,}  "
            f"{support['validation'][label]:>10,}  "
            f"{support['test'][label]:>10,}"
        )


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    dataset_dir = args.dataset_dir.resolve()
    output_dir = args.output_dir.resolve()
    csv_files = sorted(dataset_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"No CICIDS CSV files were found in {dataset_dir}. Use rich exports "
            "that retain Source IP, Destination IP, and preferably Timestamp."
        )

    print("Loading source captures:")
    for path in csv_files:
        print(f"  {path.name}")

    dataset, preprocessor = prepare_sequence_dataset(
        csv_files,
        random_state=args.random_state,
        session_gap_seconds=args.session_gap_seconds,
    )
    metadata = save_dataset_artifacts(
        dataset,
        preprocessor,
        output_dir,
        random_state=args.random_state,
    )

    print("\nLeakage-safe sequence dataset created")
    print(f"  Features: {len(SEQUENCE_FEATURES)} telemetry fields")
    print(f"  Sequence length: {SEQUENCE_LENGTH}")
    print(f"  Train groups: {metadata['train_groups']}")
    print(f"  Validation groups: {metadata['validation_groups']}")
    print(f"  Test groups: {metadata['test_groups']}")
    print(f"  Sequence counts: {metadata['dataset_sizes']}")
    print(f"  Preprocessor fitted rows: {preprocessor.training_rows:,}")
    _print_class_support(metadata)
    print(f"\nArtifacts saved in {output_dir}")
    print("  sequence_dataset.npz")
    print("  sequence_preprocessor.joblib")
    print("  label_mapping.json")
    print("  metadata.json")


if __name__ == "__main__":
    main()
