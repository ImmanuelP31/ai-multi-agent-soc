from __future__ import annotations

from datetime import datetime, timezone
import unittest

from sqlalchemy import Float, create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from agents.remediation_agent import RemediationProcessor
from backend import database
from backend.routes.alerts import get_alerts, get_stats
from common.events import (
    DetectionMetadata,
    InvestigationMetadata,
    SOCEvent,
    Severity,
    StageName,
    ThreatIntelligenceMetadata,
    ThreatMatchType,
)


def base_event(
    event: str = "network_flow_observed",
    severity: Severity = Severity.LOW,
) -> SOCEvent:
    created = SOCEvent.create_ingested(
        event=event,
        source_ip="192.0.2.10",
        user="database-test",
        observed_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )
    created.severity = severity
    return created


def enrich_event(event: SOCEvent) -> tuple[SOCEvent, SOCEvent, SOCEvent, SOCEvent]:
    detected = event.model_copy(deep=True)
    detected.severity = Severity.HIGH
    detected.detection = DetectionMetadata(
        method="isolation_forest",
        anomaly_score=0.8125,
    )
    detected = detected.advance_stage(StageName.DETECTION, "detection-agent")

    investigated = detected.model_copy(deep=True)
    investigated.investigation_metadata = InvestigationMetadata(
        summary="Sequence prediction generated.",
        method="lstm_sequence_model",
        predicted_next_attack="PortScan",
        confidence=0.734,
        model_status="loaded",
    )
    investigated = investigated.advance_stage(
        StageName.INVESTIGATION,
        "investigation-agent",
    )

    threat_enriched = investigated.model_copy(deep=True)
    threat_enriched.threat_intelligence = ThreatIntelligenceMetadata(
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="Discovery",
        mapping_version="2026-09-project-v1",
        match_type=ThreatMatchType.EXACT,
        confidence=0.83,
        evidence='event == "PortScan"',
        recommended_action="Block the scanning source.",
    )
    threat_enriched = threat_enriched.advance_stage(
        StageName.THREAT_INTEL,
        "threat-intel-agent",
    )

    remediated = RemediationProcessor().process(threat_enriched)
    return detected, investigated, threat_enriched, remediated


class DatabaseTestCase(unittest.TestCase):
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


class IncidentPersistenceTests(DatabaseTestCase):
    def test_event_upsert_reuses_the_same_row(self):
        event = base_event()

        first_id = database.persist_event(event)
        second_id = database.persist_event(event)

        self.assertEqual(first_id, second_id)
        with database.SessionLocal() as session:
            self.assertEqual(session.query(database.Incident).count(), 1)

    def test_progressive_enrichment_updates_existing_row(self):
        event = base_event()
        stages = enrich_event(event)

        row_ids = [database.persist_event(stage) for stage in stages]

        self.assertEqual(len(set(row_ids)), 1)
        with database.SessionLocal() as session:
            row = session.query(database.Incident).one()
            self.assertEqual(row.current_stage, StageName.REMEDIATION.value)
            self.assertEqual(row.detection_method, "isolation_forest")
            self.assertEqual(row.predicted_next_attack, "PortScan")
            self.assertEqual(row.mitre_technique_id, "T1046")
            self.assertEqual(row.mitre_technique_name, "Network Service Discovery")
            self.assertEqual(row.threat_intelligence_method, "exact")
            self.assertEqual(row.mitre_mapping_version, "2026-09-project-v1")
            self.assertEqual(row.mitre_evidence, 'event == "PortScan"')
            self.assertEqual(
                row.threat_intelligence_metadata["technique_id"], "T1046"
            )
            self.assertEqual(row.remediation_actions[0]["action"], "BLOCK_IP")

    def test_prediction_confidence_is_numeric(self):
        _, investigated, _, _ = enrich_event(base_event())
        database.persist_event(investigated)

        self.assertIsInstance(
            database.Incident.__table__.c.prediction_confidence.type,
            Float,
        )
        with database.SessionLocal() as session:
            row = session.query(database.Incident).one()
            self.assertIsInstance(row.prediction_confidence, float)
            self.assertAlmostEqual(row.prediction_confidence, 0.734)
            self.assertIsInstance(row.anomaly_score, float)

    def test_alert_api_exposes_structured_threat_intelligence(self):
        _, _, enriched, _ = enrich_event(base_event())
        database.persist_event(enriched)

        alert = get_alerts()[0]

        self.assertEqual(alert["threat_intelligence"]["technique_id"], "T1046")
        self.assertEqual(alert["mitre_match_type"], "exact")
        self.assertEqual(alert["mitre_mapping_version"], "2026-09-project-v1")
        self.assertEqual(alert["mitre_evidence"], 'event == "PortScan"')

    def test_duplicate_replay_does_not_erase_later_enrichment(self):
        event = base_event()
        detected, investigated, _, _ = enrich_event(event)
        database.persist_event(investigated)

        database.persist_event(detected)

        with database.SessionLocal() as session:
            row = session.query(database.Incident).one()
            self.assertEqual(row.current_stage, StageName.INVESTIGATION.value)
            self.assertEqual(row.predicted_next_attack, "PortScan")
            self.assertAlmostEqual(row.prediction_confidence, 0.734)

    def test_stats_count_logical_events_not_stage_writes(self):
        first = base_event(severity=Severity.LOW)
        second = base_event(event="malware_detected", severity=Severity.HIGH)
        for stage in enrich_event(first):
            database.persist_event(stage)
        database.persist_event(second)
        database.persist_event(second)

        stats = get_stats()

        self.assertEqual(stats["total_alerts"], 2)
        self.assertEqual(stats["severity_counts"]["HIGH"], 2)
        self.assertEqual(stats["malware_count"], 1)


class TimestampParsingTests(unittest.TestCase):
    def test_iso_timestamp_is_normalized_to_utc(self):
        parsed = database.parse_timestamp("2026-01-02T12:00:00+05:30")

        self.assertEqual(
            parsed,
            datetime(2026, 1, 2, 6, 30, tzinfo=timezone.utc),
        )

    def test_unix_timestamp_is_supported(self):
        parsed = database.parse_timestamp(0)

        self.assertEqual(parsed, datetime(1970, 1, 1, tzinfo=timezone.utc))

    def test_invalid_or_naive_timestamp_is_rejected(self):
        for value in ("not-a-timestamp", "2026-01-02T12:00:00", None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    database.parse_timestamp(value)


if __name__ == "__main__":
    unittest.main()
