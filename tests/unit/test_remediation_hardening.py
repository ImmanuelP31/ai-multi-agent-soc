from __future__ import annotations

from datetime import datetime, timezone
import json
import subprocess

import pytest
from pydantic import ValidationError

from agents import remediation_agent
from agents.remediation_agent import RemediationProcessor, remediation_log_record
from agents.threat_intel_agent import ThreatIntelProcessor
from common.events import (
    DetectionMetadata,
    SOCEvent,
    Severity,
    severity_with_threat_evidence,
)
from common.remediation import (
    ActionResult,
    RemediationAction,
    RemediationActionStatus,
    RemediationActionType,
    RemediationPolicy,
    RemediationPolicyClass,
    RemediationTargetScope,
)


FIXED_TIME = datetime(2026, 7, 8, 9, 10, tzinfo=timezone.utc)


def make_event(
    *,
    severity: Severity = Severity.HIGH,
    source_ip: str | None = "8.8.8.8",
    user: str | None = "analyst.user",
    event: str = "port_scan",
) -> SOCEvent:
    value = SOCEvent.create_ingested(
        event=event,
        source_ip=source_ip,
        user=user,
        observed_at=FIXED_TIME,
    )
    value.severity = severity
    return value


def find_action(event: SOCEvent, action_type: RemediationActionType):
    return next(
        action
        for action in event.remediation.actions
        if action.action is action_type
    )


@pytest.mark.parametrize(
    ("source_ip", "expected_target", "expected_executable"),
    [
        ("8.8.8.8", "8.8.8.8", "iptables"),
        ("2001:4860:4860:0:0:0:0:8888", "2001:4860:4860::8888", "ip6tables"),
    ],
)
def test_valid_ipv4_and_ipv6_create_normalized_argv_preview(
    source_ip,
    expected_target,
    expected_executable,
):
    result = RemediationProcessor(clock=lambda: FIXED_TIME).process(
        make_event(source_ip=source_ip)
    )

    block = find_action(result, RemediationActionType.BLOCK_IP)
    assert block.target == expected_target
    assert block.argv_preview[0] == expected_executable
    assert block.argv_preview[4] == expected_target
    assert block.status is RemediationActionStatus.DRY_RUN


def test_private_ip_is_allowed_only_as_a_validated_dry_run_target():
    result = RemediationProcessor(clock=lambda: FIXED_TIME).process(
        make_event(source_ip="10.20.30.40")
    )

    block = find_action(result, RemediationActionType.BLOCK_IP)
    assert block.target_scope is RemediationTargetScope.PRIVATE
    assert block.status is RemediationActionStatus.DRY_RUN
    assert result.remediation.dry_run is True


@pytest.mark.parametrize(
    "source_ip",
    [
        None,
        "unknown",
        "not-an-ip",
        "1.2.3.4; rm -rf /",
        "127.0.0.1",
        "::1",
        "169.254.10.20",
        "224.0.0.1",
    ],
)
def test_non_actionable_ip_never_creates_network_control(source_ip):
    result = RemediationProcessor(clock=lambda: FIXED_TIME).process(
        make_event(source_ip=source_ip)
    )

    action_types = {action.action for action in result.remediation.actions}
    assert RemediationActionType.BLOCK_IP not in action_types
    assert RemediationActionType.RATE_LIMIT_IP not in action_types
    assert RemediationActionType.ESCALATE_TO_ANALYST in action_types
    assert all(source_ip not in action.argv_preview for action in result.remediation.actions)


def test_only_declared_action_types_are_generated():
    generated = set()
    for severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
        result = RemediationProcessor(clock=lambda: FIXED_TIME).process(
            make_event(severity=severity)
        )
        generated.update(action.action for action in result.remediation.actions)

    assert generated == set(RemediationActionType)


def test_unknown_severity_is_audited_and_escalated():
    result = RemediationProcessor(clock=lambda: FIXED_TIME).process(
        make_event(severity=Severity.UNKNOWN)
    )

    assert [action.action for action in result.remediation.actions] == [
        RemediationActionType.AUDIT_LOG,
        RemediationActionType.ESCALATE_TO_ANALYST,
    ]


def test_action_contract_rejects_free_form_actions_and_command_strings():
    action = RemediationProcessor().determine_actions(make_event())[0]
    payload = action.model_dump(mode="json")
    payload["action"] = "RUN_ARBITRARY_COMMAND"

    with pytest.raises(ValidationError):
        RemediationAction.model_validate(payload)

    payload = action.model_dump(mode="json")
    payload["command"] = "iptables; shutdown now"
    with pytest.raises(ValidationError):
        RemediationAction.model_validate(payload)


def test_policy_classifies_destructive_and_safe_actions():
    policy = RemediationPolicy()

    for action in RemediationActionType:
        expected = (
            RemediationPolicyClass.REQUIRES_APPROVAL
            if action in policy.destructive_actions
            else RemediationPolicyClass.AUTOMATIC_SAFE
        )
        assert policy.classify(action) is expected


class RecordingExecutor:
    name = "recording-live-executor"
    dry_run = False

    def __init__(self):
        self.calls: list[RemediationActionType] = []

    def execute(self, action: RemediationAction) -> ActionResult:
        self.calls.append(action.action)
        return ActionResult(
            action_id=action.action_id,
            action=action.action,
            status=RemediationActionStatus.COMPLETED,
            executor=self.name,
            dry_run=False,
            processed_at=FIXED_TIME,
            detail="test executor",
        )


def test_destructive_live_action_is_blocked_without_explicit_approval():
    executor = RecordingExecutor()
    result = RemediationProcessor(
        clock=lambda: FIXED_TIME,
        executor=executor,
        destructive_execution_allowed=False,
    ).process(make_event())

    block = find_action(result, RemediationActionType.BLOCK_IP)
    flag = find_action(result, RemediationActionType.FLAG_USER_FOR_REVIEW)
    assert block.status is RemediationActionStatus.BLOCKED_BY_POLICY
    assert flag.status is RemediationActionStatus.COMPLETED
    assert executor.calls == [RemediationActionType.FLAG_USER_FOR_REVIEW]


def test_explicit_approval_allows_injected_live_executor():
    executor = RecordingExecutor()
    RemediationProcessor(
        clock=lambda: FIXED_TIME,
        executor=executor,
        destructive_execution_allowed=True,
    ).process(make_event())

    assert executor.calls == [
        RemediationActionType.BLOCK_IP,
        RemediationActionType.FLAG_USER_FOR_REVIEW,
    ]


def test_private_ip_remains_blocked_for_injected_live_executor():
    executor = RecordingExecutor()
    result = RemediationProcessor(
        clock=lambda: FIXED_TIME,
        executor=executor,
        destructive_execution_allowed=True,
    ).process(make_event(source_ip="10.20.30.40"))

    block = find_action(result, RemediationActionType.BLOCK_IP)
    assert block.status is RemediationActionStatus.BLOCKED_BY_POLICY
    assert executor.calls == [RemediationActionType.FLAG_USER_FOR_REVIEW]


def test_default_executor_never_invokes_system_commands(monkeypatch):
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("system command execution is forbidden")

    monkeypatch.setattr(subprocess, "run", fail_if_called)
    result = RemediationProcessor(clock=lambda: FIXED_TIME).process(
        make_event(severity=Severity.CRITICAL)
    )

    assert result.remediation.executor == "dry-run"
    assert all(
        action.status is RemediationActionStatus.DRY_RUN
        for action in result.remediation.actions
    )


def test_replay_keeps_action_identity_and_one_log_record(tmp_path, monkeypatch):
    processor = RemediationProcessor(clock=lambda: FIXED_TIME)
    event = make_event(severity=Severity.CRITICAL)

    first = processor.process(event)
    second = processor.process(event)

    assert [action.action_id for action in first.remediation.actions] == [
        action.action_id for action in second.remediation.actions
    ]
    assert len({action.action_id for action in first.remediation.actions}) == len(
        first.remediation.actions
    )

    log_path = tmp_path / "remediation.jsonl"
    monkeypatch.setattr(remediation_agent, "LOG_FILE", log_path)
    remediation_agent.write_remediation_log(remediation_log_record(first))
    remediation_agent.write_remediation_log(remediation_log_record(second))
    records = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert len(records) == 1


@pytest.mark.parametrize(
    (
        "severity",
        "tactic",
        "confidence",
        "match_type",
        "failed_logins",
        "expected",
    ),
    [
        (Severity.HIGH, "Impact", 0.94, "exact_match", 0, Severity.CRITICAL),
        (
            Severity.HIGH,
            "Privilege Escalation",
            0.91,
            "exact_match",
            0,
            Severity.CRITICAL,
        ),
        (
            Severity.HIGH,
            "Credential Access",
            0.95,
            "exact_match",
            10,
            Severity.CRITICAL,
        ),
        (Severity.HIGH, "Impact", 0.89, "exact_match", 0, Severity.HIGH),
        (Severity.HIGH, "Impact", 0.94, "fuzzy_keyword_match", 0, Severity.HIGH),
        (Severity.MEDIUM, "Impact", 0.94, "exact_match", 0, Severity.MEDIUM),
    ],
)
def test_critical_severity_requires_deterministic_corroborating_evidence(
    severity,
    tactic,
    confidence,
    match_type,
    failed_logins,
    expected,
):
    assert severity_with_threat_evidence(
        severity,
        tactic=tactic,
        confidence=confidence,
        match_type=match_type,
        failed_login_count=failed_logins,
    ) is expected


def test_threat_intel_stage_makes_critical_reachable():
    event = make_event(severity=Severity.HIGH, event="ddos_attempt")

    result = ThreatIntelProcessor().process(event)

    assert result.severity is Severity.CRITICAL


def test_repeated_failed_logins_can_become_critical():
    event = make_event(severity=Severity.HIGH, event="failed_login")
    event.detection = DetectionMetadata(failed_login_count=10)

    result = ThreatIntelProcessor().process(event)

    assert result.severity is Severity.CRITICAL
