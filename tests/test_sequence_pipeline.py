from __future__ import annotations

import tempfile
from pathlib import Path
import unittest
import numpy as np
import pandas as pd

from ml.sequence_detection.pipeline import (
    SEQUENCE_FEATURES,
    SEQUENCE_LENGTH,
    GroupSplit,
    SequenceArtifactError,
    SequenceDataset,
    build_sequences,
    create_metadata,
    fit_sequence_preprocessor,
    prepare_sequence_dataset,
    prepare_source_frame,
    split_source_groups,
    validate_metadata,
)


FORBIDDEN_FEATURES = {
    "attack_encoded",
    "severity_encoded",
    "attack_frequency",
    "repeated_ip",
}


def raw_frame(
    rows: int,
    *,
    base: float,
    source_ip: str | None = None,
) -> pd.DataFrame:
    data = {
        feature: np.arange(rows, dtype=float) + base + index
        for index, feature in enumerate(SEQUENCE_FEATURES)
    }
    data["Label"] = ["BENIGN" if index % 2 == 0 else "DDoS" for index in range(rows)]
    if source_ip is not None:
        data["Source IP"] = [source_ip] * rows
    return pd.DataFrame(data)


def prepared_frame(
    name: str,
    rows: int = 8,
    *,
    base: float = 1.0,
    source_ip: str | None = None,
) -> pd.DataFrame:
    frame, _ = prepare_source_frame(
        raw_frame(rows, base=base, source_ip=source_ip), name
    )
    return frame


class SequencePipelineTests(unittest.TestCase):
    def test_target_and_target_derivatives_are_not_features(self):
        self.assertNotIn("Label", SEQUENCE_FEATURES)
        self.assertTrue(FORBIDDEN_FEATURES.isdisjoint(SEQUENCE_FEATURES))

    def test_source_group_split_is_disjoint_before_windows(self):
        split = split_source_groups([f"capture-{index}.csv" for index in range(8)])

        self.assertFalse(set(split.train) & set(split.validation))
        self.assertFalse(set(split.train) & set(split.test))
        self.assertFalse(set(split.validation) & set(split.test))
        self.assertEqual(
            set(split.train) | set(split.validation) | set(split.test),
            {f"capture-{index}.csv" for index in range(8)},
        )

    def test_sequences_never_cross_entity_boundaries(self):
        first = raw_frame(7, base=1.0, source_ip="10.0.0.1")
        second = raw_frame(7, base=1000.0, source_ip="10.0.0.2")
        combined, strategy = prepare_source_frame(
            pd.concat([first, second], ignore_index=True), "capture.csv"
        )
        preprocessor = fit_sequence_preprocessor({"capture.csv": combined})

        batch = build_sequences(
            {"capture.csv": combined},
            preprocessor,
            {"BENIGN": 0, "DDoS": 1},
        )

        self.assertEqual(strategy, "Source IP")
        self.assertEqual(len(batch.y), 4)
        self.assertEqual(set(batch.entities), {
            "capture.csv::10.0.0.1",
            "capture.csv::10.0.0.2",
        })
        for sequence, entity in zip(batch.X, batch.entities):
            values = sequence[:, 0]
            if entity.endswith("10.0.0.1"):
                self.assertTrue(np.all(values < 0))
            else:
                self.assertTrue(np.all(values > 0))

    def test_sequence_shape_matches_runtime_contract(self):
        frame = prepared_frame("train.csv", rows=9)
        preprocessor = fit_sequence_preprocessor({"train.csv": frame})

        batch = build_sequences(
            {"train.csv": frame},
            preprocessor,
            {"BENIGN": 0, "DDoS": 1},
        )

        self.assertEqual(
            batch.X.shape,
            (4, SEQUENCE_LENGTH, len(SEQUENCE_FEATURES)),
        )
        self.assertEqual(batch.y.shape, (4,))
        self.assertEqual(batch.previous_class.shape, (4,))

    def test_preprocessing_state_comes_only_from_training_groups(self):
        train = prepared_frame("train.csv", rows=7, base=10.0)
        validation = prepared_frame("validation.csv", rows=7, base=1_000_000.0)

        preprocessor = fit_sequence_preprocessor({"train.csv": train})
        preprocessor.transform_frame(validation)

        expected_medians = train.loc[:, list(SEQUENCE_FEATURES)].median().to_numpy()
        np.testing.assert_allclose(preprocessor.imputer.statistics_, expected_medians)
        self.assertEqual(preprocessor.training_groups, ("train.csv",))
        self.assertEqual(preprocessor.training_rows, len(train))

    def test_dataset_generation_splits_files_before_windows(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index in range(5):
                path = Path(directory) / f"capture-{index}.csv"
                raw_frame(8, base=float(index * 100)).to_csv(path, index=False)
                paths.append(path)

            dataset, preprocessor = prepare_sequence_dataset(paths)

        dataset.split.validate()
        self.assertEqual(set(dataset.train.source_groups), set(dataset.split.train))
        self.assertEqual(
            set(dataset.validation.source_groups), set(dataset.split.validation)
        )
        self.assertEqual(set(dataset.test.source_groups), set(dataset.split.test))
        self.assertEqual(preprocessor.training_groups, dataset.split.train)

    def test_model_metadata_and_mapping_stay_consistent(self):
        split = GroupSplit(("train.csv",), ("validation.csv",), ("test.csv",))
        frames = {
            group: prepared_frame(group, rows=7, base=float(index * 100))
            for index, group in enumerate(split.train + split.validation + split.test)
        }
        preprocessor = fit_sequence_preprocessor({"train.csv": frames["train.csv"]})
        mapping = {"BENIGN": 0, "DDoS": 1}
        dataset = SequenceDataset(
            train=build_sequences({"train.csv": frames["train.csv"]}, preprocessor, mapping),
            validation=build_sequences(
                {"validation.csv": frames["validation.csv"]}, preprocessor, mapping
            ),
            test=build_sequences({"test.csv": frames["test.csv"]}, preprocessor, mapping),
            split=split,
            label_mapping=mapping,
            entity_columns={group: "source_file" for group in frames},
        )
        metadata = create_metadata(dataset, preprocessor)

        validate_metadata(metadata, mapping)
        self.assertEqual(metadata["feature_columns"], list(SEQUENCE_FEATURES))
        self.assertEqual(metadata["class_mapping"], mapping)
        broken = dict(metadata, num_classes=3)
        with self.assertRaises(SequenceArtifactError):
            validate_metadata(broken, mapping)

    def test_runtime_transform_cannot_observe_event_or_ground_truth_labels(self):
        frame = prepared_frame("train.csv", rows=7, base=10.0)
        preprocessor = fit_sequence_preprocessor({"train.csv": frame})
        telemetry = {
            feature: float(index + 1)
            for index, feature in enumerate(SEQUENCE_FEATURES)
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


if __name__ == "__main__":
    unittest.main()
