# Sequence model artifacts

The leakage-free LSTM runtime requires this complete generated set:

- `metadata.json` with `status` set to `trained`
- `label_mapping.json`
- `sequence_preprocessor.joblib`
- `sequence_model.keras`

Sequence generation requires rich CICIDS flow CSVs containing `Source IP`,
`Destination IP`, and preferably `Timestamp`. Endpoint and time fields are used
only to order flows and construct inactivity-bounded source sessions; they are
never model inputs. Whole sessions are assigned to train, validation, and test
before window generation, and generation stops unless every target class has
sequence support in all three splits.

Generate the dataset and artifacts with the training image:

```bash
docker compose --profile training run --rm ml-training \
  python ml/sequence_detection/generate_rich_sequences.py \
  --dataset-dir ml/datasets \
  --output-dir ml/sequence_detection
docker compose --profile training run --rm ml-training \
  python ml/sequence_detection/train_lstm_model.py \
  --artifact-dir ml/sequence_detection
```

The same entry points can write directly to a Kaggle working directory:

```bash
python ml/sequence_detection/generate_rich_sequences.py \
  --dataset-dir /kaggle/input/cicids-rich \
  --output-dir /kaggle/working/sequence_artifacts
python ml/sequence_detection/train_lstm_model.py \
  --artifact-dir /kaggle/working/sequence_artifacts
python scripts/evaluate_sequence_model.py \
  --artifact-dir /kaggle/working/sequence_artifacts
```

Generated model/data files are ignored by Git. `metadata.json` and
`label_mapping.json` remain versioned so the expected schema and model version
are reviewable. With `SEQUENCE_PREDICTION_MODE=required`, the Investigation
Agent exits unless TensorFlow can load the complete compatible artifact set.
The Compose default is the explicit `optional` mode; it emits an unavailable
model status and never substitutes rule-based next-attack predictions.
