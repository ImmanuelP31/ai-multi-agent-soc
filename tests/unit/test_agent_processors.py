from __future__ import annotations

from datetime import datetime, timezone
import importlib
import math
from types import SimpleNamespace

import pytest

from agents.detection_agent import DetectionProcessor
from agents.investigation_agent import InvestigationProcessor
from agents.remediation_agent import RemediationProcessor
from agents.reporting_agent import ReportingProcessor, update_summary
from agents.threat_intel_agent import ThreatIntelProcessor
from common.events import (
    InvestigationMetadata,
    SOCEvent,
    Severity,
    TelemetryPayload,
    ThreatMatchType,
)
from ml.features.network_flow import AnomalyInference, ModelBundleError
from ml.sequence_detection.predictor import (
    PredictionCandidate,
    SequencePrediction,
)


FIXED_TIME = datetime(2026, 2, 3, 4, 5, tzinfo=timezone.utc)


def make_event(
    *,
    event: str = "network_flow_observed",
    severity: Severity = Severity.LOW,
    source_ip: str | None = "192.0.2.20",
    user: str | None = "soc-user",
    features: dict[str, float] | None = None,
) -> SOCEvent:
    value = SOCEvent.create_ingested(
        event=event,
        source_ip=source_ip,
        user=user,
        observed_at=FIXED_TIME,
        telemetry=TelemetryPayload(flow_features=features or {}),
    )
    value.severity = severity
    return value


class StubBundle:
    def __init__(self, inference: AnomalyInference):
        self.inference = inference
        self.metadata = SimpleNamespace(
            model_version="test-isolation-forest",
            feature_pipeline_version="network-flow-v1",
        )
        self.thresholds = SimpleNamespace(
            version="test-thresholds",
            basis="unit-test thresholds",
            anomaly_decision_threshold=0.0,
            high_severity_decision_threshold=-0.2,
        )
        self.received = None

    def infer(self, telemetry):
        self.received = telemetry
        return self.inference


@pytest.mark.parametrize(
    ("inference", "expected_severity"),
    [
        (AnomalyInference(0.25, False, "LOW"), Severity.LOW),
        (AnomalyInference(-0.5, True, "HIGH"), Severity.HIGH),
    ],
)
def test_detection_processor_handles_benign_and_anomalous_input(
    inference,
    expected_severity,
):
    bundle = StubBundle(inference)
    event = make_event(features={"Flow Duration": 10.0})

    result = DetectionProcessor(mode="ml", bundle=bundle).process(event)

    assert result.severity is expected_severity
    assert result.detection.method == "isolation_forest"
    assert bundle.received == {"Flow Duration": 10.0}


def test_detection_processor_passes_missing_features_to_saved_pipeline():
    bundle = StubBundle(AnomalyInference(0.1, False, "LOW"))

    result = DetectionProcessor(mode="ml", bundle=bundle).process(make_event())

    assert result.severity is Severity.LOW
    assert bundle.received == {}


def test_detection_processor_requires_model_in_ml_mode():
    with pytest.raises(ModelBundleError, match="no validated anomaly bundle"):
        DetectionProcessor(mode="ml").process(make_event())


@pytest.mark.parametrize(
    "inference",
    [
        AnomalyInference(math.nan, True, "HIGH"),
        AnomalyInference(0.1, False, "UNKNOWN"),
        AnomalyInference(0.1, "yes", "LOW"),
    ],
)
def test_detection_processor_rejects_invalid_model_output(inference):
    with pytest.raises(ModelBundleError):
        DetectionProcessor(mode="ml", bundle=StubBundle(inference)).process(
            make_event()
        )


class StubSequencePredictor:
    def __init__(self, outcome=None, error: Exception | None = None):
        self.outcome = outcome
        self.error = error

    def predict(self, event):
        if self.error:
            raise self.error
        return self.outcome


def test_investigation_processor_handles_incomplete_sequence():
    outcome = SequencePrediction(
        status="warming_up",
        model_status="loaded",
        detail="Collecting 1/3 events.",
        sequence_length_used=1,
        model_version="lstm-v1",
        state_status="loaded",
    )

    result = InvestigationProcessor(StubSequencePredictor(outcome)).process(
        make_event()
    )

    assert result.investigation_metadata.predicted_next_attack is None
    assert result.investigation_metadata.method == "lstm_sequence_model_warming_up"
    assert result.investigation_metadata.sequence_length_used == 1


def test_investigation_processor_handles_complete_sequence():
    outcome = SequencePrediction(
        status="predicted",
        model_status="loaded",
        detail="ready",
        predicted_class="PortScan",
        confidence=0.81,
        top_predictions=(PredictionCandidate(1, "PortScan", 0.81),),
        sequence_length_used=3,
        model_version="lstm-v1",
        predicted_at=FIXED_TIME,
        state_status="loaded",
    )

    result = InvestigationProcessor(StubSequencePredictor(outcome)).process(
        make_event()
    )

    assert result.investigation_metadata.predicted_next_attack == "PortScan"
    assert result.investigation_metadata.confidence == pytest.approx(0.81)
    assert result.investigation_metadata.top_predictions[0].attack_class == "PortScan"


def test_investigation_processor_surfaces_model_unavailable():
    outcome = SequencePrediction(
        status="unavailable",
        model_status="missing_model_artifacts",
        detail="model file is missing",
    )

    result = InvestigationProcessor(StubSequencePredictor(outcome)).process(
        make_event()
    )

    assert result.investigation_metadata.method == "lstm_sequence_model_unavailable"
    assert result.investigation_metadata.model_status == "missing_model_artifacts"


def test_investigation_processor_rejects_corrupted_model_output():
    predictor = StubSequencePredictor(error=ValueError("non-finite probabilities"))

    with pytest.raises(ValueError, match="non-finite"):
        InvestigationProcessor(predictor).process(make_event())


def test_threat_intel_exact_match():
    result = ThreatIntelProcessor().process(make_event(event="failed_login"))

    assert result.threat_intelligence.match_type is ThreatMatchType.EXACT
    assert result.threat_intelligence.confidence == pytest.approx(0.95)
    assert result.threat_intelligence.technique_id == "T1110"


def test_threat_intel_uses_predicted_attack_mapping():
    event = make_event(event="unmapped_observation")
    event.investigation_metadata = InvestigationMetadata(
        predicted_next_attack="PortScan"
    )

    result = ThreatIntelProcessor().process(event)

    assert result.threat_intelligence.match_type is ThreatMatchType.PREDICTED_CLASS
    assert result.threat_intelligence.confidence == pytest.approx(0.79)
    assert result.threat_intelligence.technique_id == "T1046"


def test_threat_intel_fuzzy_and_unknown_matches_are_explicit():
    fuzzy = ThreatIntelProcessor().process(make_event(event="suspicious scan traffic"))
    unknown = ThreatIntelProcessor().process(make_event(event="novel behavior"))

    assert fuzzy.threat_intelligence.match_type is ThreatMatchType.FUZZY
    assert fuzzy.threat_intelligence.confidence == pytest.approx(0.60)
    assert unknown.threat_intelligence.match_type is ThreatMatchType.UNKNOWN
    assert unknown.threat_intelligence.confidence == pytest.approx(0.0)


@pytest.mark.parametrize(
    ("severity", "expected_actions"),
    [
        (Severity.LOW, ["AUDIT_LOG"]),
        (Severity.MEDIUM, ["RATE_LIMIT_IP", "INCREASE_MONITORING"]),
        (Severity.HIGH, ["BLOCK_IP", "FLAG_USER_FOR_REVIEW"]),
        (Severity.CRITICAL, ["BLOCK_IP", "ISOLATE_USER", "ESCALATE_TO_ANALYST"]),
    ],
)
def test_remediation_processor_applies_severity_policy(severity, expected_actions):
    result = RemediationProcessor(clock=lambda: FIXED_TIME).process(
        make_event(severity=severity)
    )

    assert [item.action for item in result.remediation.actions] == expected_actions
    assert result.remediation.remediated_at == FIXED_TIME


@pytest.mark.parametrize("source_ip", [None, "not-an-ip", "1.2.3.4; rm -rf /"])
def test_remediation_never_builds_commands_for_unsafe_ip(source_ip):
    result = RemediationProcessor().process(
        make_event(severity=Severity.HIGH, source_ip=source_ip)
    )

    action_types = [action.action for action in result.remediation.actions]
    assert "BLOCK_IP" not in action_types
    assert "ESCALATE_TO_ANALYST" in action_types
    assert all(source_ip not in action.argv_preview for action in result.remediation.actions)


def test_remediation_handles_missing_and_unsafe_user():
    missing = RemediationProcessor().process(
        make_event(severity=Severity.CRITICAL, user=None)
    )
    unsafe = RemediationProcessor().process(
        make_event(severity=Severity.CRITICAL, user="root; shutdown -h now")
    )

    assert "ISOLATE_USER" not in [item.action for item in missing.remediation.actions]
    unsafe_user = unsafe.remediation.actions[1]
    assert unsafe_user.action == "ESCALATE_TO_ANALYST"
    assert unsafe_user.argv_preview == []


def test_reporting_processor_keeps_identity_and_one_report(tmp_path):
    processor = ReportingProcessor(tmp_path, clock=lambda: FIXED_TIME)
    event = make_event(severity=Severity.HIGH)

    first = processor.process(event)
    second = processor.process(event)
    first_path = processor.write_report(processor.build_report(first))
    second_path = processor.write_report(processor.build_report(second))

    assert first.event_id == event.event_id
    assert first.incident_id == event.incident_id
    assert first_path == second_path
    assert list(tmp_path.glob("*.json")) == [first_path]


def test_reporting_summary_is_idempotent(tmp_path):
    processor = ReportingProcessor(tmp_path, clock=lambda: FIXED_TIME)
    report = processor.build_report(processor.process(make_event()))
    summary = {
        "total_incidents": 0,
        "by_severity": {},
        "by_tactic": {},
        "top_ips": {},
        "processed_incident_ids": [],
    }

    update_summary(summary, report)
    update_summary(summary, report)

    assert summary["total_incidents"] == 1


def test_importing_agents_does_not_initialize_infrastructure(monkeypatch):
    import backend.database

    def fail_if_called(*args, **kwargs):
        raise AssertionError("infrastructure initialized during import")

    monkeypatch.setattr(backend.database, "init_engine", fail_if_called)
    for module_name in (
        "agents.detection_agent",
        "agents.investigation_agent",
        "agents.threat_intel_agent",
        "agents.remediation_agent",
        "agents.reporting_agent",
    ):
        importlib.reload(importlib.import_module(module_name))
