from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from common.events import SOCEvent
from common.pipeline import run_stage


def event_payload():
    return SOCEvent.create_ingested(
        event="port_scan",
        source_ip="192.0.2.30",
        user="stage-test",
        observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    ).to_message()


class RecordingProcessor:
    def __init__(self, calls, error=None):
        self.calls = calls
        self.error = error

    def process(self, event):
        self.calls.append("process")
        if self.error:
            raise self.error
        return event


def test_stage_runs_in_required_order():
    calls = []
    payload = event_payload()

    result = run_stage(
        payload,
        RecordingProcessor(calls),
        lambda event: calls.append("persist"),
        after_persist=lambda event: calls.append("local_output"),
        publish=lambda event: calls.append("publish"),
    )

    assert calls == ["process", "persist", "local_output", "publish"]
    assert str(result.event_id) == payload["event_id"]


def test_database_failure_stops_local_output_and_publish():
    calls = []

    def fail_database(event):
        calls.append("persist")
        raise RuntimeError("database unavailable")

    with pytest.raises(RuntimeError, match="database unavailable"):
        run_stage(
            event_payload(),
            RecordingProcessor(calls),
            fail_database,
            after_persist=lambda event: calls.append("local_output"),
            publish=lambda event: calls.append("publish"),
        )

    assert calls == ["process", "persist"]


def test_publish_failure_occurs_only_after_processing_and_persistence():
    calls = []

    def fail_publish(event):
        calls.append("publish")
        raise RuntimeError("Kafka publish failed")

    with pytest.raises(RuntimeError, match="Kafka publish failed"):
        run_stage(
            event_payload(),
            RecordingProcessor(calls),
            lambda event: calls.append("persist"),
            after_persist=lambda event: calls.append("local_output"),
            publish=fail_publish,
        )

    assert calls == ["process", "persist", "local_output", "publish"]


def test_processor_failure_prevents_persistence():
    calls = []

    with pytest.raises(RuntimeError, match="Redis unavailable"):
        run_stage(
            event_payload(),
            RecordingProcessor(calls, RuntimeError("Redis unavailable")),
            lambda event: calls.append("persist"),
        )

    assert calls == ["process"]


def test_malformed_event_is_rejected_before_processor():
    calls = []
    payload = event_payload()
    payload.pop("event_id")

    with pytest.raises(ValidationError):
        run_stage(payload, RecordingProcessor(calls), lambda event: None)

    assert calls == []
