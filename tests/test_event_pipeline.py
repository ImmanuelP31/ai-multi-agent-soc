from __future__ import annotations

from datetime import datetime, timezone
import unittest

from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from agents import detection_agent
from agents import investigation_agent
from agents import remediation_agent
from agents import reporting_agent
from agents import threat_intel_agent
from backend import database
from common.events import GroundTruthMetadata, SOCEvent, StageName, deserialize_event


def sample_event(source_ip: str | None = "192.168.1.10") -> SOCEvent:
    return SOCEvent.create_ingested(
        event="port_scan",
        source_ip=source_ip,
        user="analyst-test",
        observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ground_truth=GroundTruthMetadata(
            synthetic=True,
            attack_label="port_scan",
            generator="unit-test",
        ),
    )


class CanonicalEventTests(unittest.TestCase):
    def test_serialization_round_trip_preserves_identity(self):
        event = sample_event()

        restored = deserialize_event(event.to_message())

        self.assertEqual(restored, event)
        self.assertEqual(restored.kafka_key(), b"192.168.1.10")

    def test_kafka_key_falls_back_to_incident_id(self):
        event = sample_event(source_ip=None)

        self.assertEqual(event.kafka_key(), str(event.incident_id).encode("utf-8"))

    def test_invalid_event_is_rejected_without_generating_identity(self):
        malformed = sample_event().to_message()
        malformed.pop("event_id")

        with self.assertRaises(ValidationError):
            deserialize_event(malformed)

        malformed = sample_event().to_message()
        malformed["incident_id"] = "not-a-uuid"
        with self.assertRaises(ValidationError):
            deserialize_event(malformed)


class PipelineIdentityTests(unittest.TestCase):
    def setUp(self):
        detection_agent.failed_login_counter.clear()
        detection_agent.failed_login_results.clear()

    def test_identity_survives_every_processing_stage(self):
        original = sample_event()
        identities = (original.event_id, original.incident_id)

        detected = detection_agent.process_event(original, mode="rule_based")
        detected = deserialize_event(detected.to_message())
        investigated = investigation_agent.process_event(detected)
        investigated = deserialize_event(investigated.to_message())
        enriched = threat_intel_agent.process_event(investigated)
        enriched = deserialize_event(enriched.to_message())
        remediated = remediation_agent.process_event(enriched)
        remediated = deserialize_event(remediated.to_message())
        reported = reporting_agent.process_event(remediated)
        reported = deserialize_event(reported.to_message())

        for event in (detected, investigated, enriched, remediated, reported):
            self.assertEqual((event.event_id, event.incident_id), identities)

        self.assertEqual(reported.stage.current_stage, StageName.REPORTING)
        self.assertEqual(
            [record.stage for record in reported.stage.history],
            [
                StageName.INGESTION,
                StageName.DETECTION,
                StageName.INVESTIGATION,
                StageName.THREAT_INTEL,
                StageName.REMEDIATION,
                StageName.REPORTING,
            ],
        )

    def test_reporting_uses_propagated_incident_id(self):
        event = reporting_agent.process_event(sample_event())

        report = reporting_agent.build_report(event)

        self.assertEqual(report["incident_id"], str(event.incident_id))
        self.assertEqual(report["event_id"], str(event.event_id))

    def test_reporting_summary_counts_replay_once(self):
        event = reporting_agent.process_event(sample_event())
        report = reporting_agent.build_report(event)
        summary = {
            "total_incidents": 0,
            "by_severity": {},
            "by_tactic": {},
            "top_ips": {},
            "processed_incident_ids": [],
        }

        reporting_agent.update_summary(summary, report)
        reporting_agent.update_summary(summary, report)

        self.assertEqual(summary["total_incidents"], 1)
        self.assertEqual(summary["processed_incident_ids"], [report["incident_id"]])


class IdempotentPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.old_engine = database._engine
        self.old_session_local = database.SessionLocal
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        database._engine = self.engine
        database.SessionLocal = sessionmaker(
            bind=self.engine,
            autoflush=False,
            autocommit=False,
        )
        database.create_test_schema(self.engine)

    def tearDown(self):
        self.engine.dispose()
        database._engine = self.old_engine
        database.SessionLocal = self.old_session_local

    def test_duplicate_delivery_updates_one_incident_row(self):
        event = sample_event()
        detected = detection_agent.process_event(event, mode="rule_based")

        first_id = database.persist_event(detected)
        second_id = database.persist_event(detected)
        investigated = investigation_agent.process_event(detected)
        third_id = database.persist_event(investigated)

        session = database.SessionLocal()
        try:
            rows = session.query(database.Incident).all()
            self.assertEqual(len(rows), 1)
            self.assertEqual(first_id, second_id)
            self.assertEqual(second_id, third_id)
            self.assertEqual(rows[0].event_id, str(event.event_id))
            self.assertEqual(rows[0].incident_id, str(event.incident_id))
            self.assertEqual(rows[0].current_stage, StageName.INVESTIGATION.value)
            self.assertIsNotNone(rows[0].investigation_metadata)
        finally:
            session.close()

    def test_replayed_earlier_stage_does_not_erase_later_enrichment(self):
        event = sample_event()
        detected = detection_agent.process_event(event, mode="rule_based")
        investigated = investigation_agent.process_event(detected)
        database.persist_event(investigated)

        database.persist_event(detected)

        session = database.SessionLocal()
        try:
            row = session.query(database.Incident).one()
            self.assertEqual(row.current_stage, StageName.INVESTIGATION.value)
            self.assertIsNotNone(row.investigation_metadata)
            self.assertEqual(
                row.investigation_method,
                investigated.investigation_metadata.method,
            )
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
