"""Canonical, progressively enriched incident persistence."""

from __future__ import annotations

from datetime import datetime, timezone
import os
import re
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    func,
    select,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from common.events import SOCEvent, StageName, deserialize_event


JSON_DOCUMENT = JSON().with_variant(JSONB, "postgresql")


class Base(DeclarativeBase):
    pass


class Incident(Base):
    """One authoritative row progressively enriched by every pipeline stage."""

    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("event_id", name="uq_incidents_event_id"),
        Index("ix_incidents_incident_id", "incident_id"),
        Index("ix_incidents_observed_at", "observed_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)

    event: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    detection_method: Mapped[str | None] = mapped_column(String(128), nullable=True)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    detection_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        JSON_DOCUMENT, nullable=True
    )

    investigation: Mapped[str | None] = mapped_column(Text, nullable=True)
    investigation_method: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    predicted_next_attack: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    prediction_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    sequence_model_status: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    investigation_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        JSON_DOCUMENT, nullable=True
    )

    mitre_technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mitre_technique_name: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    mitre_tactic: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mitre_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    recommended_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    threat_intelligence_method: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    threat_intelligence_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        JSON_DOCUMENT, nullable=True
    )

    telemetry: Mapped[dict[str, Any] | None] = mapped_column(
        JSON_DOCUMENT, nullable=True
    )
    remediation_actions: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSON_DOCUMENT, nullable=True
    )
    remediation_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        JSON_DOCUMENT, nullable=True
    )
    reporting_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        JSON_DOCUMENT, nullable=True
    )
    stage_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        JSON_DOCUMENT, nullable=True
    )
    ground_truth: Mapped[dict[str, Any] | None] = mapped_column(
        JSON_DOCUMENT, nullable=True
    )
    original_payload: Mapped[dict[str, Any] | None] = mapped_column(
        JSON_DOCUMENT, nullable=True
    )

    current_stage: Mapped[str] = mapped_column(String(64), nullable=False)
    processing_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    processing_version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


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
    """Verify database connectivity; Alembic owns production schema changes."""

    engine = init_engine()
    with engine.connect() as connection:
        connection.execute(select(1))


def create_test_schema(engine) -> None:
    """Create the canonical schema only for isolated unit-test databases."""

    Base.metadata.create_all(bind=engine)


def parse_timestamp(value: Any) -> datetime:
    """Parse supported timestamp forms and normalize them to UTC."""

    if isinstance(value, bool) or value is None:
        raise ValueError(f"Invalid timestamp: {value!r}")
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        try:
            parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError(f"Invalid Unix timestamp: {value!r}") from exc
    elif isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            raise ValueError("Invalid timestamp: empty string")
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Invalid ISO-8601 timestamp: {value!r}") from exc
    else:
        raise ValueError(f"Unsupported timestamp type: {type(value).__name__}")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"Timestamp must include timezone information: {value!r}")
    return parsed.astimezone(timezone.utc)


def timestamp_from_alert(alert: dict[str, Any]) -> datetime:
    value = alert.get("observed_at")
    if value is None:
        value = alert.get("timestamp")
    return parse_timestamp(value)


def _as_event(value: SOCEvent | dict[str, Any]) -> SOCEvent:
    if isinstance(value, SOCEvent):
        return value
    return deserialize_event(value)


def split_mitre_technique(value: str | None) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    match = re.match(r"^\s*(T\d{4}(?:\.\d{3})?)\s*(.*)$", value)
    if not match:
        return None, value.strip()
    technique_id, remainder = match.groups()
    technique_name = re.sub(r"^[^A-Za-z0-9]+", "", remainder).strip() or None
    return technique_id, technique_name


STAGE_ORDER = {
    StageName.INGESTION.value: 0,
    StageName.DETECTION.value: 1,
    StageName.INVESTIGATION.value: 2,
    StageName.THREAT_INTEL.value: 3,
    StageName.REMEDIATION.value: 4,
    StageName.REPORTING.value: 5,
}


def _apply_event(row: Incident, event: SOCEvent) -> None:
    payload = event.model_dump(mode="json")
    observed_at = parse_timestamp(event.observed_at)
    incoming_rank = STAGE_ORDER[event.stage.current_stage.value]
    stored_rank = STAGE_ORDER.get(row.current_stage or "", -1)
    now = datetime.now(timezone.utc)

    row.event_id = str(event.event_id)
    row.incident_id = str(event.incident_id)
    row.schema_version = event.schema_version
    row.event = event.event
    row.severity = event.severity.value
    row.source_ip = event.source_ip
    row.user = event.user
    row.observed_at = observed_at
    row.telemetry = payload["telemetry"]

    if incoming_rank >= STAGE_ORDER[StageName.DETECTION.value]:
        row.detection_method = event.detection.method
        row.anomaly_score = event.detection.anomaly_score
        row.detection_metadata = payload["detection"]

    if incoming_rank >= STAGE_ORDER[StageName.INVESTIGATION.value]:
        row.investigation = event.investigation_metadata.summary
        row.investigation_method = event.investigation_metadata.method
        row.predicted_next_attack = (
            event.investigation_metadata.predicted_next_attack
        )
        row.prediction_confidence = event.investigation_metadata.confidence
        row.sequence_model_status = event.investigation_metadata.model_status
        row.investigation_metadata = payload["investigation_metadata"]

    if incoming_rank >= STAGE_ORDER[StageName.THREAT_INTEL.value]:
        technique_id, technique_name = split_mitre_technique(
            event.threat_intelligence.mitre_attack
        )
        row.mitre_technique_id = technique_id
        row.mitre_technique_name = technique_name
        row.mitre_tactic = event.threat_intelligence.mitre_tactic
        row.mitre_confidence = event.threat_intelligence.confidence
        row.recommended_action = event.threat_intelligence.recommended_action
        row.threat_intelligence_method = event.threat_intelligence.method
        row.threat_intelligence_metadata = payload["threat_intelligence"]

    if incoming_rank >= STAGE_ORDER[StageName.REMEDIATION.value]:
        row.remediation_actions = payload["remediation"]["actions"]
        row.remediation_metadata = payload["remediation"]

    if incoming_rank >= STAGE_ORDER[StageName.REPORTING.value]:
        row.reporting_metadata = payload["reporting"]

    if payload.get("ground_truth") is not None:
        row.ground_truth = payload["ground_truth"]
    if payload.get("original") is not None:
        row.original_payload = payload["original"]

    if incoming_rank >= stored_rank:
        row.stage_metadata = payload["stage"]
        row.current_stage = event.stage.current_stage.value
        row.processing_timestamp = parse_timestamp(
            event.stage.processing_timestamp
        )
        row.processing_version = event.stage.processing_version
    if row.created_at is None:
        row.created_at = now
    row.updated_at = now


def persist_event(value: SOCEvent | dict[str, Any]) -> int:
    """Insert once by event_id, then enrich that same incident row."""

    event = _as_event(value)
    init_engine()
    session = SessionLocal()

    try:
        row = session.scalar(
            select(Incident)
            .where(Incident.event_id == str(event.event_id))
            .with_for_update()
        )
        if row is None:
            now = datetime.now(timezone.utc)
            row = Incident(
                event_id=str(event.event_id),
                incident_id=str(event.incident_id),
                schema_version=event.schema_version,
                event=event.event,
                severity=event.severity.value,
                observed_at=parse_timestamp(event.observed_at),
                current_stage=event.stage.current_stage.value,
                processing_timestamp=parse_timestamp(
                    event.stage.processing_timestamp
                ),
                processing_version=event.stage.processing_version,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
        _apply_event(row, event)
        session.commit()
        return row.id
    except IntegrityError:
        session.rollback()
        row = session.scalar(
            select(Incident)
            .where(Incident.event_id == str(event.event_id))
            .with_for_update()
        )
        if row is None:
            raise
        _apply_event(row, event)
        session.commit()
        return row.id
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def persist_alert(alert: SOCEvent | dict[str, Any]) -> int:
    """Backward-compatible persistence entry point."""

    return persist_event(alert)
