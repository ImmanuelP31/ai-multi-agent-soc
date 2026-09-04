"""Re-evaluate saved sequence models on the untouched grouped test split."""

from __future__ import annotations

import json
from pathlib import Path
import sys

_repo_root = Path(__file__).resolve().parents[2]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from ml.sequence_detection.pipeline import (
    MarkovBaseline,
    evaluate_probabilities,
    load_dataset_artifact,
    load_preprocessor,
    validate_metadata,
)


THIS_DIR = Path(__file__).resolve().parent


def main() -> None:
    with open(THIS_DIR / "metadata.json", encoding="utf-8") as file:
        metadata = json.load(file)
    with open(THIS_DIR / "label_mapping.json", encoding="utf-8") as file:
        label_mapping = json.load(file)
    validate_metadata(metadata, label_mapping)
    load_preprocessor(THIS_DIR / "sequence_preprocessor.joblib")
    arrays = load_dataset_artifact(THIS_DIR / "sequence_dataset.npz")

    try:
        from tensorflow.keras.models import load_model
    except ImportError as exc:
        raise RuntimeError("TensorFlow is required to evaluate the LSTM") from exc

    model_path = THIS_DIR / str(metadata["model_artifact"])
    if not model_path.is_file() or metadata.get("status") != "trained":
        raise FileNotFoundError(
            f"A trained compatible model is required at {model_path}. "
            "Run train_lstm_model.py first."
        )
    model = load_model(model_path)
    lstm_probabilities = model.predict(arrays["X_test"], verbose=0)
    lstm_metrics = evaluate_probabilities(
        arrays["y_test"], lstm_probabilities, label_mapping
    )

    baseline = MarkovBaseline.fit(
        arrays["previous_train"], arrays["y_train"], len(label_mapping)
    )
    markov_metrics = evaluate_probabilities(
        arrays["y_test"],
        baseline.predict_proba(arrays["previous_test"]),
        label_mapping,
    )

    print("Held-out grouped test results")
    for name, metrics in (("LSTM", lstm_metrics), ("Markov", markov_metrics)):
        print(
            f"  {name}: accuracy={metrics['accuracy']:.4f}, "
            f"macro_f1={metrics['macro_f1']:.4f}, "
            f"weighted_f1={metrics['weighted_f1']:.4f}, "
            f"top_3={metrics['top_3_accuracy']:.4f}"
        )
    print("\nLSTM per-class metrics")
    print(json.dumps(lstm_metrics["per_class"], indent=2))
    print("\nLSTM confusion matrix")
    print(json.dumps(lstm_metrics["confusion_matrix"]))


if __name__ == "__main__":
    main()
