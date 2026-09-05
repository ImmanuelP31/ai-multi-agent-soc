# Anomaly model artifacts

The runtime consumes one generated artifact:

- `anomaly_bundle.joblib`: Isolation Forest, fitted imputer, fitted scaler,
  ordered feature names, thresholds, and version metadata.

The bundle is intentionally not committed. Build it from the repository's
training data with:

```bash
python ml/training/train_anomaly_model.py
python ml/training/evaluate_anomaly_model.py
```

Set `DETECTION_MODE=ml` only after this file exists. The default Docker Compose
configuration uses the explicit `rule_based` demo mode and reports that mode in
every detection result and in readiness output.
