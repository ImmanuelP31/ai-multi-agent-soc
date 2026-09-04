"""Replay-safe PostgreSQL persistence for canonical SOC events."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import JSON, DateTime, Index, Integer, String, create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from common.events import SOCEvent, StageName, deserialize_event


class Base(DeclarativeBase):
    pass


class SocAlert(Base):
    """One progressively enriched row per canonical event."""

    __tablename__ = "soc_alerts"
    __table_args__ = (
        Index("uq_soc_alerts_event_id", "event_id", unique=True),
        Index("ix_soc_alerts_incident_id", "incident_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    incident_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    schema_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    event: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(64))
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    observed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    telemetry: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    detection_metadata: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )
    investigation_metadata: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )
    threat_intelligence_metadata: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )
    remediation_metadata: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )
    reporting_metadata: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )
    stage_metadata: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    ground_truth: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    original_payload: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)

    current_stage: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    processing_timestamp: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    processing_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Legacy projections retained for the existing API and dashboard.
    investigation: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    investigation_method: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )
    mitre_attack: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    predicted_next_attack: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    confidence: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    lstm_status: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    agent_source: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)


def get_database_url() -> str:
    return os.environ.get(
        "DATABASE_URL",
        "postgresql://socuser:socpass@localhost:5432/socdb",
    )


_engine = None
SessionLocal = None


def init_engine():
    global _engine, SessionLocal
    if _engine is None:
        _engine = create_engine(get_database_url(), pool_pre_ping=True)
        SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)
    return _engine


def init_db() -> None:
    """Create the table and evolve an existing local schema in place."""

    engine = init_engine()
    Base.metadata.create_all(bind=engine)
    ensure_soc_alert_schema(engine)


def ensure_soc_alert_schema(engine) -> None:
    inspector = inspect(engine)
    if not inspector.has_table(SocAlert.__tablename__):
        return

    existing_columns = {
        column["name"] for column in inspector.get_columns(SocAlert.__tablename__)
    }
    expected_columns = {
        "event_id": "VARCHAR(36)",
        "incident_id": "VARCHAR(36)",
        "schema_version": "VARCHAR(32)",
        "source_ip": "VARCHAR(64)",
        "ip": "VARCHAR(64)",
        "user": "VARCHAR(255)",
        "observed_at": "TIMESTAMP WITH TIME ZONE",
        "telemetry": "JSON",
        "detection_metadata": "JSON",
        "investigation_metadata": "JSON",
        "threat_intelligence_metadata": "JSON",
        "remediation_metadata": "JSON",
        "reporting_metadata": "JSON",
        "stage_metadata": "JSON",
        "ground_truth": "JSON",
        "original_payload": "JSON",
        "current_stage": "VARCHAR(64)",
        "processing_timestamp": "TIMESTAMP WITH TIME ZONE",
        "processing_version": "VARCHAR(64)",
        "last_updated_at": "TIMESTAMP WITH TIME ZONE",
        "investigation": "VARCHAR(1000)",
        "investigation_method": "VARCHAR(128)",
        "mitre_attack": "VARCHAR(255)",
        "predicted_next_attack": "VARCHAR(255)",
        "confidence": "VARCHAR(64)",
        "lstm_status": "VARCHAR(128)",
        "agent_source": "VARCHAR(128)",
    }

    with engine.begin() as connection:
        for name, column_type in expected_columns.items():
            if name in existing_columns:
                continue
            quoted_name = f'"{name}"' if name == "user" else name
            connection.execute(
                text(
                    f"ALTER TABLE {SocAlert.__tablename__} "
                    f"ADD COLUMN {quoted_name} {column_type}"
                )
            )

        connection.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_soc_alerts_event_id "
                "ON soc_alerts (event_id)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_soc_alerts_incident_id "
                "ON soc_alerts (incident_id)"
            )
        )


def timestamp_from_alert(alert: dict[str, Any]) -> datetime:
    ts = alert.get("observed_at", alert.get("timestamp"))
    if ts is None:
        return datetime.now(timezone.utc)
    if isinstance(ts, datetime):
        return ts
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    if isinstance(ts, str):
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    raise ValueError(f"Unsupported event timestamp: {ts!r}")


def _as_event(value: SOCEvent | dict[str, Any]) -> SOCEvent:
    if isinstance(value, SOCEvent):
        return value
    return deserialize_event(value)


def _apply_event(row: SocAlert, event: SOCEvent) -> None:
    payload = event.model_dump(mode="json")
    observed_at = timestamp_from_alert(payload)
    stage_order = {
        StageName.INGESTION.value: 0,
        StageName.DETECTION.value: 1,
        StageName.INVESTIGATION.value: 2,
        StageName.THREAT_INTEL.value: 3,
        StageName.REMEDIATION.value: 4,
        StageName.REPORTING.value: 5,
    }
    incoming_rank = stage_order[event.stage.current_stage.value]
    stored_rank = stage_order.get(row.current_stage or "", -1)

    row.event_id = str(event.event_id)
    row.incident_id = str(event.incident_id)
    row.schema_version = event.schema_version
    row.event = event.event
    row.severity = event.severity.value
    row.source_ip = event.source_ip
    row.ip = event.source_ip
    row.user = event.user
    row.observed_at = observed_at
    row.timestamp = observed_at
    row.telemetry = payload["telemetry"]
    if incoming_rank >= 1:
        row.detection_metadata = payload["detection"]
    if incoming_rank >= 2:
        row.investigation_metadata = payload["investigation_metadata"]
        row.investigation = event.investigation_metadata.summary
        row.investigation_method = event.investigation_metadata.method
        row.predicted_next_attack = (
            event.investigation_metadata.predicted_next_attack
        )
        row.confidence = (
            str(event.investigation_metadata.confidence)
            if event.investigation_metadata.confidence is not None
            else None
        )
        row.lstm_status = event.investigation_metadata.model_status
    if incoming_rank >= 3:
        row.threat_intelligence_metadata = payload["threat_intelligence"]
        row.mitre_attack = event.threat_intelligence.mitre_attack
    if incoming_rank >= 4:
        row.remediation_metadata = payload["remediation"]
    if incoming_rank >= 5:
        row.reporting_metadata = payload["reporting"]

    if payload.get("ground_truth") is not None:
        row.ground_truth = payload["ground_truth"]
    if payload.get("original") is not None:
        row.original_payload = payload["original"]

    if incoming_rank >= stored_rank:
        row.stage_metadata = payload["stage"]
        row.current_stage = event.stage.current_stage.value
        row.processing_timestamp = event.stage.processing_timestamp
        row.processing_version = event.stage.processing_version
        row.last_updated_at = event.stage.last_updated_at
        row.agent_source = event.stage.processor


def persist_event(value: SOCEvent | dict[str, Any]) -> int:
    """Insert once by event_id, then update the same row at later stages."""

    event = _as_event(value)
    init_engine()
    session = SessionLocal()

    try:
        row = (
            session.query(SocAlert)
            .filter(SocAlert.event_id == str(event.event_id))
            .with_for_update()
            .one_or_none()
        )
        if row is None:
            row = SocAlert(
                event=event.event,
                severity=event.severity.value,
                timestamp=event.observed_at,
            )
            session.add(row)
        _apply_event(row, event)
        session.commit()
        return row.id
    except IntegrityError:
        session.rollback()
        row = (
            session.query(SocAlert)
            .filter(SocAlert.event_id == str(event.event_id))
            .with_for_update()
            .one()
        )
        _apply_event(row, event)
        session.commit()
        return row.id
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def persist_alert(alert: SOCEvent | dict[str, Any]) -> int:
    """Backward-compatible name for existing callers."""

    return persist_event(alert)
