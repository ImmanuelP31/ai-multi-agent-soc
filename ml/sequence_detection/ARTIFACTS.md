# Sequence model artifacts

The leakage-free LSTM runtime requires this complete generated set:

- `metadata.json` with `status` set to `trained`
- `label_mapping.json`
- `sequence_preprocessor.joblib`
- `sequence_model.keras`

Generate the dataset and artifacts with the training image:

```bash
docker compose --profile training run --rm ml-training \
  python ml/sequence_detection/generate_rich_sequences.py
docker compose --profile training run --rm ml-training \
  python ml/sequence_detection/train_lstm_model.py
```

Generated model/data files are ignored by Git. `metadata.json` and
`label_mapping.json` remain versioned so the expected schema and model version
are reviewable. With `SEQUENCE_PREDICTION_MODE=required`, the Investigation
Agent exits unless TensorFlow can load the complete compatible artifact set.
The Compose default is the explicit `optional` mode; it emits an unavailable
model status and never substitutes rule-based next-attack predictions.
