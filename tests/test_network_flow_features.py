from __future__ import annotations

from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd

from agents import detection_agent
from common.events import GroundTruthMetadata, SOCEvent, TelemetryPayload
from ml.features.network_flow import (
    FEATURE_PIPELINE_VERSION,
    NETWORK_FLOW_FEATURES,
    InvalidTelemetryError,
    ModelBundleError,
    canonical_feature_frame,
    fit_anomaly_bundle,
    load_anomaly_bundle,
    save_anomaly_bundle,
    telemetry_feature_frame,
)
from scripts.attack_simulator import create_attack
from ml.training.evaluate_anomaly_model import evaluate_anomaly_model


def training_frame(rows: int = 80) -> pd.DataFrame:
    rng = np.random.default_rng(42)
    data = {
        feature: rng.normal(loc=(index + 1) * 100.0, scale=10.0, size=rows)
        for index, feature in enumerate(NETWORK_FLOW_FEATURES)
    }
    frame = pd.DataFrame(data)
    frame.loc[0, NETWORK_FLOW_FEATURES[0]] = np.nan
    frame.loc[1, NETWORK_FLOW_FEATURES[1]] = np.inf
    return frame


def complete_telemetry() -> dict[str, float]:
    return {
        feature: float((index + 1) * 100)
        for index, feature in enumerate(NETWORK_FLOW_FEATURES)
    }


class NetworkFlowFeatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frame = training_frame()
        cls.bundle = fit_anomaly_bundle(cls.frame)

    def test_training_and_runtime_use_exact_feature_order(self):
        training = canonical_feature_frame(self.frame)
        runtime = telemetry_feature_frame(complete_telemetry())

        self.assertEqual(tuple(training.columns), NETWORK_FLOW_FEATURES)
        self.assertEqual(tuple(runtime.columns), NETWORK_FLOW_FEATURES)
        self.assertEqual(self.bundle.feature_names, NETWORK_FLOW_FEATURES)
        self.assertEqual(
            self.bundle.metadata.feature_pipeline_version,
            FEATURE_PIPELINE_VERSION,
        )

    def test_missing_telemetry_uses_training_imputer(self):
        incomplete = complete_telemetry()
        incomplete.pop(NETWORK_FLOW_FEATURES[0])
        incomplete[NETWORK_FLOW_FEATURES[1]] = None

        transformed = self.bundle.transform_telemetry(incomplete)

        self.assertEqual(transformed.shape, (1, len(NETWORK_FLOW_FEATURES)))
        self.assertTrue(np.isfinite(transformed).all())
        expected_medians = canonical_feature_frame(self.frame).median().to_numpy()
        np.testing.assert_allclose(
            self.bundle.imputer.statistics_,
            expected_medians,
        )

    def test_invalid_numeric_telemetry_is_rejected(self):
        telemetry = complete_telemetry()
        telemetry[NETWORK_FLOW_FEATURES[3]] = "not-a-number"

        with self.assertRaises(InvalidTelemetryError):
            telemetry_feature_frame(telemetry)

    def test_preprocessing_is_deterministic(self):
        telemetry = complete_telemetry()

        first = self.bundle.transform_telemetry(telemetry)
        second = self.bundle.transform_telemetry(telemetry)

        np.testing.assert_array_equal(first, second)

    def test_model_bundle_can_be_saved_and_loaded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "anomaly_bundle.joblib"
            save_anomaly_bundle(self.bundle, path)

            loaded = load_anomaly_bundle(path)

        self.assertEqual(loaded.feature_names, NETWORK_FLOW_FEATURES)
        self.assertEqual(
            loaded.thresholds,
            self.bundle.thresholds,
        )
        np.testing.assert_array_equal(
            loaded.transform_telemetry(complete_telemetry()),
            self.bundle.transform_telemetry(complete_telemetry()),
        )

    def test_evaluation_reuses_bundle_preprocessing_and_saves_metrics(self):
        test_frame = training_frame(20)
        test_frame["Label"] = [0] * 10 + [1] * 10
        original_statistics = self.bundle.imputer.statistics_.copy()
        with tempfile.TemporaryDirectory() as directory:
            bundle_path = Path(directory) / "anomaly_bundle.joblib"
            output_path = Path(directory) / "evaluation.json"
            save_anomaly_bundle(self.bundle, bundle_path)
            with patch(
                "ml.training.evaluate_anomaly_model.pd.read_parquet",
                return_value=test_frame,
            ):
                metrics = evaluate_anomaly_model(
                    Path("unused-test-dataset.parquet"),
                    bundle_path,
                    output_path,
                )

            self.assertTrue(output_path.is_file())

        np.testing.assert_array_equal(
            self.bundle.imputer.statistics_,
            original_statistics,
        )
        for metric in (
            "precision",
            "recall",
            "f1",
            "confusion_matrix",
            "false_positive_rate",
            "false_negative_rate",
            "detection_rate",
        ):
            self.assertIn(metric, metrics)

    def test_ml_inference_ignores_event_and_ground_truth_labels(self):
        telemetry = TelemetryPayload(flow_features=complete_telemetry())
        first = SOCEvent.create_ingested(
            event="port_scan",
            source_ip="192.168.1.10",
            user="test",
            telemetry=telemetry,
            ground_truth=GroundTruthMetadata(attack_label="DDoS"),
        )
        second = SOCEvent.create_ingested(
            event="malware_detected",
            source_ip="192.168.1.20",
            user="test",
            telemetry=telemetry,
            ground_truth=GroundTruthMetadata(attack_label="BENIGN"),
        )

        first_result = detection_agent.process_event(
            first,
            mode="ml",
            bundle=self.bundle,
        )
        second_result = detection_agent.process_event(
            second,
            mode="ml",
            bundle=self.bundle,
        )

        self.assertEqual(
            first_result.detection.anomaly_score,
            second_result.detection.anomaly_score,
        )
        self.assertEqual(first_result.severity, second_result.severity)

    def test_missing_model_fails_in_ml_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.joblib"
            with self.assertRaises(ModelBundleError):
                detection_agent.load_detection_runtime("ml", missing)

    def test_rule_fallback_must_be_explicit_and_is_visible(self):
        telemetry = complete_telemetry()
        telemetry["Flow Packets/s"] = 150_000.0
        event = SOCEvent.create_ingested(
            event="network_flow_observed",
            source_ip="192.168.1.10",
            user=None,
            telemetry=TelemetryPayload(flow_features=telemetry),
        )

        result = detection_agent.process_event(event, mode="rule_based")

        self.assertEqual(result.severity.value, "HIGH")
        self.assertEqual(result.detection.method, "rule_based_fallback")
        self.assertEqual(result.detection.model_status, "explicit_fallback")
        self.assertFalse(result.detection.model_available)
        self.assertEqual(
            result.detection.threshold_version,
            detection_agent.FALLBACK_RULE_VERSION,
        )
        self.assertIsNone(
            detection_agent.load_detection_runtime(
                "rule_based",
                Path("bundle-is-not-required-in-fallback-mode.joblib"),
            )
        )

    def test_simulator_emits_complete_telemetry_and_separate_ground_truth(self):
        event = create_attack("port_scan", random.Random(7))

        self.assertEqual(event.event, "network_flow_observed")
        self.assertEqual(
            tuple(event.telemetry.flow_features),
            NETWORK_FLOW_FEATURES,
        )
        self.assertEqual(event.ground_truth.attack_label, "port_scan")


if __name__ == "__main__":
    unittest.main()
