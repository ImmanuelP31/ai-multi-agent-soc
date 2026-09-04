"""Canonical event contract shared by every SOC pipeline stage."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


SCHEMA_VERSION = "1.0"
PROCESSING_VERSION = "1.0.0"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class StageName(str, Enum):
    INGESTION = "ingestion"
    DETECTION = "detection"
    INVESTIGATION = "investigation"
    THREAT_INTEL = "threat_intel"
    REMEDIATION = "remediation"
    REPORTING = "reporting"


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TelemetryPayload(ContractModel):
    flow_features: dict[str, float] = Field(default_factory=dict)
    packet_rate: float | None = None
    attack_frequency: int | None = None
    repeated_ip: bool | None = None
    failed_login_count: int | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class DetectionMetadata(ContractModel):
    method: str | None = None
    anomaly_score: float | None = None
    decision_score: float | None = None
    model_available: bool | None = None
    model_status: str | None = None
    model_version: str | None = None
    feature_pipeline_version: str | None = None
    threshold_version: str | None = None
    threshold_basis: str | None = None
    thresholds: dict[str, float] = Field(default_factory=dict)
    failed_login_count: int | None = None


class SequencePredictionCandidate(ContractModel):
    rank: int = Field(ge=1)
    attack_class: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)


class InvestigationMetadata(ContractModel):
    summary: str | None = None
    method: str | None = None
    predicted_next_attack: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    model_status: str | None = None
    top_predictions: list[SequencePredictionCandidate] = Field(default_factory=list)
    sequence_length_used: int | None = Field(default=None, ge=0)
    model_version: str | None = None
    prediction_timestamp: datetime | None = None
    sequence_state_backend: str | None = None
    sequence_state_status: str | None = None


class ThreatIntelligenceMetadata(ContractModel):
    mitre_attack: str | None = None
    mitre_tactic: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    recommended_action: str | None = None
    method: str | None = None


class RemediationAction(ContractModel):
    action: str
    target: str | None = None
    status: str
    command: str | None = None
    note: str | None = None
    event: str | None = None


class RemediationMetadata(ContractModel):
    actions: list[RemediationAction] = Field(default_factory=list)
    remediated_at: datetime | None = None


class ReportingMetadata(ContractModel):
    generated_at: datetime | None = None
    report_path: str | None = None


class StageRecord(ContractModel):
    stage: StageName
    processed_at: datetime
    processing_version: str


class StageMetadata(ContractModel):
    current_stage: StageName = StageName.INGESTION
    processing_timestamp: datetime = Field(default_factory=utc_now)
    processing_version: str = PROCESSING_VERSION
    last_updated_at: datetime = Field(default_factory=utc_now)
    processor: str = "attack-simulator"
    history: list[StageRecord] = Field(default_factory=list)


class GroundTruthMetadata(ContractModel):
    synthetic: bool = True
    attack_label: str | None = None
    expected_severity: Severity | None = None
    generator: str | None = None


class SOCEvent(ContractModel):
    """One event that is progressively enriched without changing identity."""

    event_id: UUID
    incident_id: UUID
    schema_version: str = Field(default=SCHEMA_VERSION, min_length=1)
    observed_at: datetime
    event: str = Field(min_length=1)
    source_ip: str | None = None
    user: str | None = None
    telemetry: TelemetryPayload = Field(default_factory=TelemetryPayload)
    severity: Severity = Severity.UNKNOWN
    detection: DetectionMetadata = Field(default_factory=DetectionMetadata)
    investigation_metadata: InvestigationMetadata = Field(
        default_factory=InvestigationMetadata
    )
    threat_intelligence: ThreatIntelligenceMetadata = Field(
        default_factory=ThreatIntelligenceMetadata
    )
    remediation: RemediationMetadata = Field(default_factory=RemediationMetadata)
    reporting: ReportingMetadata = Field(default_factory=ReportingMetadata)
    stage: StageMetadata = Field(default_factory=StageMetadata)
    ground_truth: GroundTruthMetadata | None = None
    original: dict[str, Any] | None = None

    @model_validator(mode="before")
    @classmethod
    def accept_legacy_projections(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value

        data = dict(value)
        if "source_ip" not in data and "ip" in data:
            data["source_ip"] = data["ip"]
        data.pop("ip", None)

        if "observed_at" not in data and "timestamp" in data:
            data["observed_at"] = data["timestamp"]
        data.pop("timestamp", None)

        detection = dict(data.get("detection") or {})
        for old, new in (
            ("detection_method", "method"),
            ("anomaly_score", "anomaly_score"),
            ("failed_login_count", "failed_login_count"),
        ):
            if old in data and new not in detection:
                detection[new] = data[old]
            data.pop(old, None)
        if detection:
            data["detection"] = detection

        investigation = dict(data.get("investigation_metadata") or {})
        if isinstance(data.get("investigation"), str):
            investigation.setdefault("summary", data["investigation"])
        data.pop("investigation", None)
        for old, new in (
            ("investigation_method", "method"),
            ("predicted_next_attack", "predicted_next_attack"),
            ("confidence", "confidence"),
            ("lstm_status", "model_status"),
        ):
            if old in data and new not in investigation:
                investigation[new] = data[old]
            data.pop(old, None)
        if investigation:
            data["investigation_metadata"] = investigation

        threat_intelligence = dict(data.get("threat_intelligence") or {})
        for old, new in (
            ("mitre_attack", "mitre_attack"),
            ("mitre_tactic", "mitre_tactic"),
            ("mitre_confidence", "confidence"),
            ("recommended_action", "recommended_action"),
            ("threat_intel_method", "method"),
        ):
            if old in data and new not in threat_intelligence:
                threat_intelligence[new] = data[old]
            data.pop(old, None)
        if threat_intelligence:
            data["threat_intelligence"] = threat_intelligence

        remediation = dict(data.get("remediation") or {})
        if "remediation_actions" in data and "actions" not in remediation:
            remediation["actions"] = data["remediation_actions"]
        if "remediated_at" in data and "remediated_at" not in remediation:
            remediation["remediated_at"] = data["remediated_at"]
        data.pop("remediation_actions", None)
        data.pop("remediation_count", None)
        data.pop("remediated_at", None)
        if remediation:
            data["remediation"] = remediation

        data.pop("agent_source", None)
        return data

    @classmethod
    def create_ingested(
        cls,
        *,
        event: str,
        source_ip: str | None,
        user: str | None,
        observed_at: datetime | None = None,
        telemetry: TelemetryPayload | None = None,
        ground_truth: GroundTruthMetadata | None = None,
        original: dict[str, Any] | None = None,
    ) -> "SOCEvent":
        """Create identity only at ingestion."""

        now = observed_at or utc_now()
        return cls(
            event_id=uuid4(),
            incident_id=uuid4(),
            observed_at=now,
            event=event,
            source_ip=source_ip,
            user=user,
            telemetry=telemetry or TelemetryPayload(),
            ground_truth=ground_truth,
            original=original,
            stage=StageMetadata(
                current_stage=StageName.INGESTION,
                processing_timestamp=now,
                last_updated_at=now,
                processor="attack-simulator",
                history=[
                    StageRecord(
                        stage=StageName.INGESTION,
                        processed_at=now,
                        processing_version=PROCESSING_VERSION,
                    )
                ],
            ),
        )

    def advance_stage(
        self,
        stage: StageName,
        processor: str,
        processing_version: str = PROCESSING_VERSION,
    ) -> "SOCEvent":
        updated = self.model_copy(deep=True)
        now = utc_now()
        history = [record for record in updated.stage.history if record.stage != stage]
        history.append(
            StageRecord(
                stage=stage,
                processed_at=now,
                processing_version=processing_version,
            )
        )
        updated.stage = StageMetadata(
            current_stage=stage,
            processing_timestamp=now,
            processing_version=processing_version,
            last_updated_at=now,
            processor=processor,
            history=history,
        )
        return updated

    def to_message(self) -> dict[str, Any]:
        """Serialize canonical data plus temporary legacy read projections."""

        payload = self.model_dump(mode="json")
        payload.update(
            {
                "ip": self.source_ip,
                "timestamp": self.observed_at.isoformat(),
                "detection_method": self.detection.method,
                "anomaly_score": self.detection.anomaly_score,
                "failed_login_count": self.detection.failed_login_count,
                "investigation": self.investigation_metadata.summary,
                "investigation_method": self.investigation_metadata.method,
                "predicted_next_attack": (
                    self.investigation_metadata.predicted_next_attack
                ),
                "confidence": self.investigation_metadata.confidence,
                "lstm_status": self.investigation_metadata.model_status,
                "mitre_attack": self.threat_intelligence.mitre_attack,
                "mitre_tactic": self.threat_intelligence.mitre_tactic,
                "mitre_confidence": self.threat_intelligence.confidence,
                "recommended_action": self.threat_intelligence.recommended_action,
                "threat_intel_method": self.threat_intelligence.method,
                "remediation_actions": [
                    action.model_dump(mode="json")
                    for action in self.remediation.actions
                ],
                "remediation_count": len(self.remediation.actions),
                "remediated_at": (
                    self.remediation.remediated_at.isoformat()
                    if self.remediation.remediated_at
                    else None
                ),
                "agent_source": self.stage.processor,
            }
        )
        return payload

    def kafka_key(self) -> bytes:
        return (self.source_ip or str(self.incident_id)).encode("utf-8")


def deserialize_event(payload: dict[str, Any]) -> SOCEvent:
    """Validate a Kafka payload without creating missing identity."""

    return SOCEvent.model_validate(payload)
