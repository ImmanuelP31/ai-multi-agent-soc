from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from uuid import UUID

import pytest
from sqlalchemy import create_engine, text

from common.events import SOCEvent, TelemetryPayload
from common.kafka import SOC_TOPICS, check_kafka, create_producer, publish_event


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("RUN_INTEGRATION") != "1",
        reason="set RUN_INTEGRATION=1 inside the Compose test stack",
    ),
]

EVENT_ID = UUID("10000000-0000-4000-8000-000000000006")
INCIDENT_ID = UUID("20000000-0000-4000-8000-000000000006")
REPORT_PATH = Path("/app/logs/reports") / f"{INCIDENT_ID}.json"


def wait_for_reporting(engine, previous_updated_at=None):
    deadline = time.monotonic() + float(
        os.environ.get("PIPELINE_TIMEOUT_SECONDS", "60")
    )
    while time.monotonic() < deadline:
        with engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT event_id, incident_id, current_stage, detection_method, "
                    "investigation_method, mitre_technique_id, remediation_actions, "
                    "remediation_metadata, "
                    "updated_at FROM incidents WHERE event_id = :event_id"
                ),
                {"event_id": str(EVENT_ID)},
            ).mappings().one_or_none()
        if row and row["current_stage"] == "reporting":
            if previous_updated_at is None or row["updated_at"] > previous_updated_at:
                return row
        time.sleep(0.5)
    raise AssertionError("Timed out waiting for the event to reach reporting")


def test_replayed_event_produces_one_enriched_incident_and_report():
    assert set(SOC_TOPICS).issubset(check_kafka())

    engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
    event = SOCEvent.create_ingested(
        event="port_scan",
        source_ip="192.0.2.66",
        user="integration-user",
        observed_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        telemetry=TelemetryPayload(
            flow_features={
                "Flow Packets/s": 20_000.0,
                "Flow Bytes/s": 6_000_000.0,
            }
        ),
    )
    event.event_id = EVENT_ID
    event.incident_id = INCIDENT_ID

    with engine.begin() as connection:
        connection.execute(
            text("DELETE FROM incidents WHERE event_id = :event_id"),
            {"event_id": str(EVENT_ID)},
        )
    REPORT_PATH.unlink(missing_ok=True)

    producer = create_producer()
    try:
        publish_event(producer, "soc_logs", event)
        first = wait_for_reporting(engine)

        assert first["incident_id"] == str(INCIDENT_ID)
        assert first["detection_method"] == "rule_based_fallback"
        assert first["investigation_method"]
        assert first["mitre_technique_id"] == "T1046"
        assert first["remediation_actions"]
        assert first["remediation_metadata"]["dry_run"] is True
        assert all(
            "command" not in action and isinstance(action["argv_preview"], list)
            for action in first["remediation_actions"]
        )
        assert REPORT_PATH.is_file()

        report = json.loads(REPORT_PATH.read_text())
        assert report["event_id"] == str(EVENT_ID)
        assert report["incident_id"] == str(INCIDENT_ID)

        publish_event(producer, "soc_logs", event)
        second = wait_for_reporting(engine, previous_updated_at=first["updated_at"])
        assert [action["action_id"] for action in second["remediation_actions"]] == [
            action["action_id"] for action in first["remediation_actions"]
        ]
    finally:
        producer.close(timeout=5)

    with engine.connect() as connection:
        count = connection.scalar(
            text("SELECT count(*) FROM incidents WHERE event_id = :event_id"),
            {"event_id": str(EVENT_ID)},
        )

    assert count == 1
    assert list(REPORT_PATH.parent.glob(f"{INCIDENT_ID}*.json")) == [REPORT_PATH]
