from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import numpy as np
import pandas as pd

from agents.investigation_agent import process_event
from common.events import SOCEvent, TelemetryPayload
from ml.sequence_detection.pipeline import (
    SEQUENCE_FEATURES,
    SEQUENCE_MODEL_VERSION,
    SEQUENCE_PIPELINE_VERSION,
    fit_sequence_preprocessor,
    prepare_source_frame,
    save_preprocessor,
)
from ml.sequence_detection.predictor import (
    RedisSequenceStore,
    SequencePredictor,
    SequenceStateUnavailable,
)


class InMemoryRedis:
    def __init__(self):
        self.lists = {}
        self.expirations = {}

    def eval(
        self,
        script,
        numkeys,
        key,
        event_id,
        item_json,
        sequence_length,
        ttl_seconds,
    ):
        self.asserted_script = script
        if numkeys != 1:
            raise AssertionError("Sequence script must operate on exactly one key")
        items = self.lists.setdefault(key, [])
        if not any(json.loads(item)["event_id"] == event_id for item in items):
            items.append(item_json)
            self.lists[key] = items[-int(sequence_length) :]
        self.expirations[key] = int(ttl_seconds)
        return list(self.lists[key])


class UnavailableRedis:
    def eval(self, *args):
        raise ConnectionError("redis is temporarily unavailable")


class FixedModel:
    def __init__(self, probabilities, sequence_length=3):
        self.probabilities = np.asarray(probabilities, dtype=np.float32)
        self.calls = []
        self.input_shape = (None, sequence_length, len(SEQUENCE_FEATURES))
        self.output_shape = (None, len(self.probabilities))

    def predict(self, values, verbose=0):
        self.calls.append(np.asarray(values))
        return np.asarray([self.probabilities])


def training_preprocessor():
    rows = 20
    data = {
        feature: np.arange(rows, dtype=float) + index + 1
        for index, feature in enumerate(SEQUENCE_FEATURES)
    }
    data["Label"] = ["BENIGN", "DDoS"] * (rows // 2)
    frame, _ = prepare_source_frame(pd.DataFrame(data), "train.csv")
    return fit_sequence_preprocessor({"train.csv": frame})


def event_for(source_ip: str, value: float) -> SOCEvent:
    telemetry = {
        feature: value + index
        for index, feature in enumerate(SEQUENCE_FEATURES)
    }
    return SOCEvent.create_ingested(
        event="network_flow_observed",
        source_ip=source_ip,
        user=None,
        telemetry=TelemetryPayload(flow_features=telemetry),
    )


def make_predictor(
    redis_client,
    *,
    sequence_length=3,
    ttl_seconds=120,
    probabilities=(0.1, 0.7, 0.2),
):
    return SequencePredictor(
        store=RedisSequenceStore(
            redis_client,
            sequence_length=sequence_length,
            ttl_seconds=ttl_seconds,
        ),
        model=FixedModel(probabilities),
        preprocessor=training_preprocessor(),
        label_mapping={0: "BENIGN", 1: "DDoS", 2: "PortScan"},
        sequence_length=sequence_length,
        model_version="lstm-next-event-test",
        model_status="loaded",
    )


class SequencePredictorTests(unittest.TestCase):
    def test_artifact_loader_uses_saved_model_and_preprocessor_contract(self):
        preprocessor = training_preprocessor()
        mapping = {"BENIGN": 0, "DDoS": 1, "PortScan": 2}
        metadata = {
            "status": "trained",
            "model_version": SEQUENCE_MODEL_VERSION,
            "sequence_pipeline_version": SEQUENCE_PIPELINE_VERSION,
            "sequence_length": 3,
            "num_features": len(SEQUENCE_FEATURES),
            "feature_columns": list(SEQUENCE_FEATURES),
            "num_classes": len(mapping),
            "class_mapping": mapping,
            "model_artifact": "sequence_model.keras",
            "preprocessor": {"artifact": "sequence_preprocessor.joblib"},
        }

        with tempfile.TemporaryDirectory() as directory:
            artifact_dir = Path(directory)
            (artifact_dir / "metadata.json").write_text(json.dumps(metadata))
            (artifact_dir / "label_mapping.json").write_text(json.dumps(mapping))
            (artifact_dir / "sequence_model.keras").write_bytes(b"test-model")
            save_preprocessor(
                preprocessor,
                artifact_dir / "sequence_preprocessor.joblib",
            )
            predictor = SequencePredictor.from_artifacts(
                InMemoryRedis(),
                artifact_dir,
                model_loader=lambda path: FixedModel((0.1, 0.7, 0.2)),
            )

        self.assertTrue(predictor.available)
        self.assertEqual(
            predictor.preprocessor.feature_names,
            preprocessor.feature_names,
        )
        np.testing.assert_array_equal(
            predictor.preprocessor.imputer.statistics_,
            preprocessor.imputer.statistics_,
        )
        self.assertEqual(predictor.model_version, SEQUENCE_MODEL_VERSION)

    def test_interleaved_sources_keep_independent_windows(self):
        redis_client = InMemoryRedis()
        predictor = make_predictor(redis_client)

        outcomes = []
        for index in range(3):
            outcomes.append(predictor.predict(event_for("10.0.0.1", index + 1)))
            outcomes.append(predictor.predict(event_for("10.0.0.2", index + 101)))

        first_key = "soc:sequence:10.0.0.1"
        second_key = "soc:sequence:10.0.0.2"
        self.assertEqual(len(redis_client.lists[first_key]), 3)
        self.assertEqual(len(redis_client.lists[second_key]), 3)
        first_values = [
            json.loads(item)["features"][0]
            for item in redis_client.lists[first_key]
        ]
        second_values = [
            json.loads(item)["features"][0]
            for item in redis_client.lists[second_key]
        ]
        self.assertTrue(max(first_values) < min(second_values))
        self.assertEqual(outcomes[-2].status, "predicted")
        self.assertEqual(outcomes[-1].status, "predicted")

    def test_redis_window_is_bounded_and_ttl_is_refreshed(self):
        redis_client = InMemoryRedis()
        predictor = make_predictor(redis_client, ttl_seconds=3600)

        for index in range(8):
            predictor.predict(event_for("10.0.0.3", index + 1))

        key = "soc:sequence:10.0.0.3"
        self.assertEqual(len(redis_client.lists[key]), 3)
        self.assertEqual(redis_client.expirations[key], 3600)

    def test_new_predictor_instance_reloads_existing_state(self):
        redis_client = InMemoryRedis()
        first_runtime = make_predictor(redis_client)
        first_runtime.predict(event_for("10.0.0.4", 1))
        first_runtime.predict(event_for("10.0.0.4", 2))

        restarted_runtime = make_predictor(redis_client)
        outcome = restarted_runtime.predict(event_for("10.0.0.4", 3))

        self.assertEqual(outcome.status, "predicted")
        self.assertEqual(outcome.sequence_length_used, 3)

    def test_runtime_uses_saved_training_preprocessor(self):
        redis_client = InMemoryRedis()
        predictor = make_predictor(redis_client)
        event = event_for("10.0.0.5", 50)

        predictor.predict(event)

        stored = json.loads(redis_client.lists["soc:sequence:10.0.0.5"][0])
        expected = predictor.preprocessor.transform_telemetry(
            event.telemetry.flow_features
        )[0]
        np.testing.assert_allclose(stored["features"], expected)

    def test_redis_unavailable_fails_for_kafka_retry(self):
        predictor = make_predictor(UnavailableRedis())

        with self.assertRaisesRegex(
            SequenceStateUnavailable,
            "Redis sequence update failed",
        ):
            predictor.predict(event_for("10.0.0.6", 1))

    def test_top_prediction_mapping_and_investigation_metadata(self):
        redis_client = InMemoryRedis()
        predictor = make_predictor(redis_client)
        for value in (1, 2):
            predictor.predict(event_for("10.0.0.7", value))

        event = event_for("10.0.0.7", 3)
        outcome = predictor.predict(event)
        investigated = process_event(event, predictor)
        restored = SOCEvent.model_validate(investigated.to_message())

        self.assertEqual(outcome.predicted_class, "DDoS")
        self.assertEqual(
            [candidate.attack_class for candidate in outcome.top_predictions],
            ["DDoS", "PortScan", "BENIGN"],
        )
        self.assertEqual(
            investigated.investigation_metadata.predicted_next_attack,
            "DDoS",
        )
        self.assertEqual(len(investigated.investigation_metadata.top_predictions), 3)
        self.assertEqual(investigated.investigation_metadata.sequence_length_used, 3)
        self.assertEqual(
            investigated.investigation_metadata.model_version,
            "lstm-next-event-test",
        )
        self.assertIsNotNone(
            investigated.investigation_metadata.prediction_timestamp
        )
        self.assertEqual(
            restored.investigation_metadata.top_predictions,
            investigated.investigation_metadata.top_predictions,
        )

    def test_replayed_event_is_not_appended_twice(self):
        redis_client = InMemoryRedis()
        predictor = make_predictor(redis_client)
        event = event_for("10.0.0.8", 1)

        predictor.predict(event)
        predictor.predict(event)

        self.assertEqual(len(redis_client.lists["soc:sequence:10.0.0.8"]), 1)


if __name__ == "__main__":
    unittest.main()
