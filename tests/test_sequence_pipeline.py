from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

import numpy as np
import pandas as pd

from ml.sequence_detection.generate_rich_sequences import (
    main as generate_main,
    parse_args as parse_generate_args,
)
from ml.sequence_detection.pipeline import (
    DESTINATION_ID_COLUMN,
    ENTITY_COLUMN,
    EVENT_TIME_COLUMN,
    SEQUENCE_FEATURES,
    SEQUENCE_LENGTH,
    SOURCE_ID_COLUMN,
    SequenceArtifactError,
    SequenceDataError,
    build_sequences,
    create_metadata,
    dataset_class_support,
    fit_sequence_preprocessor,
    prepare_sequence_dataset,
    prepare_source_frame,
    split_entity_groups,
    validate_array_class_coverage,
    validate_metadata,
)
from ml.sequence_detection.train_lstm_model import (
    load_training_artifacts,
    parse_args as parse_train_args,
)


FORBIDDEN_FEATURES = {
    "Source IP",
    "Destination IP",
    "Timestamp",
    "attack_encoded",
    "severity_encoded",
    "attack_frequency",
    "repeated_ip",
}


def raw_frame(
    rows: int,
    *,
    base: float,
    source_ip: str = "10.0.0.1",
    destination_ip: str = "192.0.2.1",
    start: str = "2026-01-01T00:00:00Z",
    labels: list[str] | None = None,
) -> pd.DataFrame:
    data = {
        feature: np.arange(rows, dtype=float) + base + index
        for index, feature in enumerate(SEQUENCE_FEATURES)
    }
    data["Label"] = labels or [
        "BENIGN" if index % 2 == 0 else "DDoS" for index in range(rows)
    ]
    data["Source IP"] = [source_ip] * rows
    data["Destination IP"] = [destination_ip] * rows
    data["Timestamp"] = pd.date_range(start, periods=rows, freq="s")
    return pd.DataFrame(data)


def prepared_frame(
    name: str,
    rows: int = 10,
    *,
    base: float = 1.0,
    source_ip: str = "10.0.0.1",
) -> pd.DataFrame:
    frame, _ = prepare_source_frame(
        raw_frame(rows, base=base, source_ip=source_ip),
        name,
    )
    return frame


def multi_session_frame(session_count: int = 15, rows_per_session: int = 10):
    frames = [
        raw_frame(
            rows_per_session,
            base=float(index * 100),
            source_ip=f"10.0.0.{index + 1}",
            destination_ip=f"192.0.2.{(index % 4) + 1}",
        )
        for index in range(session_count)
    ]
    return pd.concat(frames, ignore_index=True)


class SequencePipelineTests(unittest.TestCase):
    def test_target_identity_and_target_derivatives_are_not_features(self):
        self.assertNotIn("Label", SEQUENCE_FEATURES)
        self.assertTrue(FORBIDDEN_FEATURES.isdisjoint(SEQUENCE_FEATURES))

    def test_rich_endpoint_columns_are_required(self):
        frame = raw_frame(10, base=1.0).drop(columns=["Source IP", "Destination IP"])

        with self.assertRaisesRegex(SequenceDataError, "not a rich flow export"):
            prepare_source_frame(frame, "reduced.csv")

    def test_timestamp_orders_rows_without_entering_model_features(self):
        frame = raw_frame(10, base=1.0).iloc[::-1].reset_index(drop=True)

        prepared, strategy = prepare_source_frame(frame, "capture.csv")

        self.assertTrue(prepared[EVENT_TIME_COLUMN].is_monotonic_increasing)
        self.assertIn("ordered by Timestamp", strategy)
        self.assertNotIn(SOURCE_ID_COLUMN, SEQUENCE_FEATURES)
        self.assertNotIn(DESTINATION_ID_COLUMN, SEQUENCE_FEATURES)
        self.assertNotIn(EVENT_TIME_COLUMN, SEQUENCE_FEATURES)

    def test_whole_session_split_is_disjoint_and_class_covered(self):
        prepared, _ = prepare_source_frame(
            multi_session_frame(),
            "capture.csv",
        )

        split = split_entity_groups({"capture.csv": prepared})

        split.validate()
        all_entities = set(prepared[ENTITY_COLUMN].unique())
        self.assertEqual(
            set(split.train) | set(split.validation) | set(split.test),
            all_entities,
        )

    def test_split_rejects_class_seen_in_fewer_than_three_sessions(self):
        frames = []
        for index in range(4):
            labels = ["BENIGN"] * 10
            if index == 0:
                labels[-1] = "DDoS"
            frames.append(
                raw_frame(
                    10,
                    base=float(index * 100),
                    source_ip=f"10.0.1.{index + 1}",
                    labels=labels,
                )
            )
        prepared, _ = prepare_source_frame(
            pd.concat(frames, ignore_index=True),
            "capture.csv",
        )

        with self.assertRaisesRegex(SequenceDataError, "DDoS=1"):
            split_entity_groups({"capture.csv": prepared})

    def test_training_artifact_validation_rejects_zero_class_support(self):
        arrays = {
            "y_train": np.array([0, 0], dtype=np.int32),
            "y_validation": np.array([0, 1], dtype=np.int32),
            "y_test": np.array([0, 1], dtype=np.int32),
        }

        with self.assertRaisesRegex(SequenceDataError, "train: DDoS"):
            validate_array_class_coverage(arrays, {"BENIGN": 0, "DDoS": 1})

    def test_sequences_never_cross_session_boundaries(self):
        first = raw_frame(7, base=1.0, source_ip="10.0.0.1")
        second = raw_frame(7, base=1000.0, source_ip="10.0.0.2")
        combined, strategy = prepare_source_frame(
            pd.concat([first, second], ignore_index=True),
            "capture.csv",
        )
        preprocessor = fit_sequence_preprocessor({"capture.csv": combined})

        batch = build_sequences(
            {"capture.csv": combined},
            preprocessor,
            {"BENIGN": 0, "DDoS": 1},
        )

        self.assertIn("Source IP ordered by Timestamp", strategy)
        self.assertEqual(len(batch.y), 4)
        self.assertEqual(
            set(batch.entities),
            {
                "capture.csv::10.0.0.1::session-0",
                "capture.csv::10.0.0.2::session-0",
            },
        )
        for sequence, entity in zip(batch.X, batch.entities):
            values = sequence[:, 0]
            if "10.0.0.1" in entity:
                self.assertTrue(np.all(values < 0))
            else:
                self.assertTrue(np.all(values > 0))

    def test_inactivity_gap_starts_a_new_session(self):
        frame = raw_frame(12, base=1.0)
        frame.loc[6:, "Timestamp"] = pd.date_range(
            "2026-01-01T02:00:00Z",
            periods=6,
            freq="s",
        )

        prepared, _ = prepare_source_frame(
            frame,
            "capture.csv",
            session_gap_seconds=3600,
        )

        self.assertEqual(prepared[ENTITY_COLUMN].nunique(), 2)

    def test_sequence_shape_matches_runtime_contract(self):
        frame = prepared_frame("train.csv")
        preprocessor = fit_sequence_preprocessor({"train.csv": frame})

        batch = build_sequences(
            {"train.csv": frame},
            preprocessor,
            {"BENIGN": 0, "DDoS": 1},
        )

        self.assertEqual(
            batch.X.shape,
            (5, SEQUENCE_LENGTH, len(SEQUENCE_FEATURES)),
        )
        self.assertEqual(batch.y.shape, (5,))
        self.assertEqual(batch.previous_class.shape, (5,))

    def test_preprocessing_state_comes_only_from_training_sessions(self):
        train = prepared_frame("train.csv", base=10.0)
        validation = prepared_frame("validation.csv", base=1_000_000.0)
        train_group = str(train[ENTITY_COLUMN].iloc[0])

        preprocessor = fit_sequence_preprocessor(
            {"train.csv": train},
            training_groups=(train_group,),
        )
        preprocessor.transform_frame(validation)

        expected_medians = train.loc[:, list(SEQUENCE_FEATURES)].median().to_numpy()
        np.testing.assert_allclose(preprocessor.imputer.statistics_, expected_medians)
        self.assertEqual(preprocessor.training_groups, (train_group,))
        self.assertEqual(preprocessor.training_rows, len(train))

    def test_dataset_generation_splits_sessions_before_windows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.csv"
            multi_session_frame().to_csv(path, index=False)

            dataset, preprocessor = prepare_sequence_dataset([path])

        dataset.split.validate()
        self.assertEqual(set(dataset.train.source_groups), set(dataset.split.train))
        self.assertEqual(
            set(dataset.validation.source_groups), set(dataset.split.validation)
        )
        self.assertEqual(set(dataset.test.source_groups), set(dataset.split.test))
        self.assertEqual(preprocessor.training_groups, dataset.split.train)
        for split_support in dataset_class_support(dataset).values():
            self.assertTrue(all(count > 0 for count in split_support.values()))

    def test_model_metadata_and_mapping_stay_consistent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.csv"
            multi_session_frame().to_csv(path, index=False)
            dataset, preprocessor = prepare_sequence_dataset([path])

        metadata = create_metadata(dataset, preprocessor)

        validate_metadata(metadata, dataset.label_mapping)
        self.assertTrue(metadata["class_coverage_validated"])
        self.assertEqual(metadata["feature_columns"], list(SEQUENCE_FEATURES))
        self.assertEqual(metadata["class_mapping"], dataset.label_mapping)
        broken = dict(metadata, num_classes=3)
        with self.assertRaises(SequenceArtifactError):
            validate_metadata(broken, dataset.label_mapping)

    def test_runtime_transform_cannot_observe_event_or_ground_truth_labels(self):
        frame = prepared_frame("train.csv", base=10.0)
        preprocessor = fit_sequence_preprocessor({"train.csv": frame})
        telemetry = {
            feature: float(index + 1) for index, feature in enumerate(SEQUENCE_FEATURES)
        }
        first_event = {"event": "DDoS", "ground_truth": "DDoS", "telemetry": telemetry}
        second_event = {
            "event": "BENIGN",
            "ground_truth": "BENIGN",
            "telemetry": telemetry,
        }

        first_vector = preprocessor.transform_telemetry(first_event["telemetry"])
        second_vector = preprocessor.transform_telemetry(second_event["telemetry"])

        np.testing.assert_array_equal(first_vector, second_vector)

    def test_cli_paths_are_configurable(self):
        generate = parse_generate_args(
            ["--dataset-dir", "input", "--output-dir", "artifacts"]
        )
        train = parse_train_args(["--artifact-dir", "artifacts"])

        self.assertEqual(generate.dataset_dir, Path("input"))
        self.assertEqual(generate.output_dir, Path("artifacts"))
        self.assertEqual(train.artifact_dir, Path("artifacts"))

    def test_cli_writes_and_reloads_artifacts_from_custom_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset_dir = root / "input"
            artifact_dir = root / "output"
            dataset_dir.mkdir()
            multi_session_frame().to_csv(dataset_dir / "rich.csv", index=False)

            generate_main(
                [
                    "--dataset-dir",
                    str(dataset_dir),
                    "--output-dir",
                    str(artifact_dir),
                ]
            )
            arrays, metadata = load_training_artifacts(artifact_dir)

        self.assertGreater(len(arrays["y_train"]), 0)
        self.assertEqual(metadata["status"], "prepared")
        self.assertTrue(metadata["class_coverage_validated"])


if __name__ == "__main__":
    unittest.main()
