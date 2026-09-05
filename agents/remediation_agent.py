"""Policy-gated, typed remediation planning with a safe dry-run executor."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from common.events import RemediationMetadata, SOCEvent, Severity, StageName
from common.remediation import (
    REMEDIATION_POLICY_VERSION,
    ActionResult,
    DryRunExecutor,
    RemediationAction,
    RemediationActionType,
    RemediationExecutor,
    RemediationPolicy,
    RemediationTargetScope,
    RemediationTargetType,
    ValidatedIP,
    blocked_action_result,
    stable_action_id,
    validate_ip_target,
)


LOG_DIR = _repo_root / "logs"
LOG_FILE = LOG_DIR / "remediation_actions.jsonl"
REMEDIATION_EXECUTION_MODE = os.environ.get(
    "REMEDIATION_EXECUTION_MODE",
    "dry_run",
).strip().lower()


def write_remediation_log(record: dict) -> None:
    """Append one replay-safe dry-run record per canonical event."""

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    event_id = record.get("event_id")
    if event_id and LOG_FILE.exists():
        with LOG_FILE.open(encoding="utf-8") as existing:
            for line in existing:
                try:
                    if json.loads(line).get("event_id") == event_id:
                        return
                except json.JSONDecodeError:
                    continue
    with LOG_FILE.open("a", encoding="utf-8") as output:
        output.write(json.dumps(record, default=str) + "\n")


def _validated_user(value: str | None) -> str | None:
    if value and re.fullmatch(r"[A-Za-z0-9_.@-]{1,255}", value):
        return value
    return None


def _parse_bool(value: str, variable: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{variable} must be true or false, got {value!r}")


def _argv_preview(
    action: RemediationActionType,
    target: str,
    ip_version: int | None = None,
) -> list[str]:
    """Build a display-only argv list after target validation."""

    if action is RemediationActionType.BLOCK_IP:
        executable = "ip6tables" if ip_version == 6 else "iptables"
        return [executable, "-A", "INPUT", "-s", target, "-j", "DROP"]
    if action is RemediationActionType.RATE_LIMIT_IP:
        executable = "ip6tables" if ip_version == 6 else "iptables"
        return [
            executable,
            "-A",
            "INPUT",
            "-s",
            target,
            "-m",
            "hashlimit",
            "--hashlimit-above",
            "10/min",
            "--hashlimit-mode",
            "srcip",
            "-j",
            "DROP",
        ]
    if action is RemediationActionType.ISOLATE_USER:
        return ["usermod", "--lock", target]
    return []


class RemediationProcessor:
    """Plan validated actions and execute them through a mandatory policy gate."""

    def __init__(
        self,
        clock: Callable[[], datetime] | None = None,
        *,
        executor: RemediationExecutor | None = None,
        policy: RemediationPolicy | None = None,
        destructive_execution_allowed: bool = False,
    ) -> None:
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.executor = executor or DryRunExecutor(clock=self.clock)
        self.policy = policy or RemediationPolicy()
        self.destructive_execution_allowed = destructive_execution_allowed

    def _action(
        self,
        event: SOCEvent,
        action_type: RemediationActionType,
        target_type: RemediationTargetType,
        target: str,
        note: str,
        *,
        target_scope: RemediationTargetScope = (
            RemediationTargetScope.NOT_APPLICABLE
        ),
        ip_version: int | None = None,
    ) -> RemediationAction:
        return RemediationAction(
            action_id=stable_action_id(
                event.incident_id,
                action_type,
                target_type,
                target,
            ),
            action=action_type,
            target_type=target_type,
            target=target,
            target_scope=target_scope,
            policy=self.policy.classify(action_type),
            argv_preview=_argv_preview(action_type, target, ip_version),
            note=note,
        )

    def _ip_action(
        self,
        event: SOCEvent,
        action_type: RemediationActionType,
        target: ValidatedIP,
        note: str,
    ) -> RemediationAction:
        return self._action(
            event,
            action_type,
            RemediationTargetType.IP,
            target.value,
            note,
            target_scope=target.scope,
            ip_version=target.version,
        )

    def _escalation(self, event: SOCEvent, reasons: list[str]) -> RemediationAction:
        return self._action(
            event,
            RemediationActionType.ESCALATE_TO_ANALYST,
            RemediationTargetType.INCIDENT,
            str(event.incident_id),
            "; ".join(dict.fromkeys(reasons)),
        )

    def determine_actions(self, event: SOCEvent) -> list[RemediationAction]:
        valid_ip = validate_ip_target(event.source_ip)
        valid_user = _validated_user(event.user)
        actions: list[RemediationAction] = []
        escalation_reasons: list[str] = []

        if event.severity is Severity.CRITICAL:
            if valid_ip:
                actions.append(
                    self._ip_action(
                        event,
                        RemediationActionType.BLOCK_IP,
                        valid_ip,
                        "Block the validated source pending analyst review.",
                    )
                )
            else:
                escalation_reasons.append("Source IP is missing or non-actionable")
            if valid_user:
                actions.append(
                    self._action(
                        event,
                        RemediationActionType.ISOLATE_USER,
                        RemediationTargetType.USER,
                        valid_user,
                        "Isolate the validated user identity pending investigation.",
                    )
                )
            else:
                escalation_reasons.append("User identity is missing or invalid")
            escalation_reasons.insert(
                0,
                f"CRITICAL incident for {event.event!r} requires analyst response",
            )

        elif event.severity is Severity.HIGH:
            if valid_ip:
                actions.append(
                    self._ip_action(
                        event,
                        RemediationActionType.BLOCK_IP,
                        valid_ip,
                        "Block the validated high-severity source.",
                    )
                )
            else:
                escalation_reasons.append("Source IP is missing or non-actionable")
            if valid_user:
                actions.append(
                    self._action(
                        event,
                        RemediationActionType.FLAG_USER_FOR_REVIEW,
                        RemediationTargetType.USER,
                        valid_user,
                        "Flag the validated user identity for analyst review.",
                    )
                )
            else:
                escalation_reasons.append("User identity is missing or invalid")

        elif event.severity is Severity.MEDIUM:
            if valid_ip:
                actions.append(
                    self._ip_action(
                        event,
                        RemediationActionType.RATE_LIMIT_IP,
                        valid_ip,
                        "Rate-limit the validated source while monitoring continues.",
                    )
                )
                monitoring_target = valid_ip.value
                monitoring_type = RemediationTargetType.IP
                monitoring_scope = valid_ip.scope
            else:
                escalation_reasons.append("Source IP is missing or non-actionable")
                monitoring_target = str(event.incident_id)
                monitoring_type = RemediationTargetType.INCIDENT
                monitoring_scope = RemediationTargetScope.NOT_APPLICABLE
            actions.append(
                self._action(
                    event,
                    RemediationActionType.INCREASE_MONITORING,
                    monitoring_type,
                    monitoring_target,
                    "Increase telemetry review for the affected source or incident.",
                    target_scope=monitoring_scope,
                )
            )

        else:
            actions.append(
                self._action(
                    event,
                    RemediationActionType.AUDIT_LOG,
                    RemediationTargetType.INCIDENT,
                    str(event.incident_id),
                    (
                        f"Record {event.severity.value} event "
                        f"{event.event!r} for audit."
                    ),
                )
            )
            if event.severity is Severity.UNKNOWN:
                escalation_reasons.append(
                    "Incident severity is UNKNOWN and requires classification"
                )

        if escalation_reasons:
            actions.append(self._escalation(event, escalation_reasons))
        return actions

    def _execute(self, action: RemediationAction) -> ActionResult:
        if not self.policy.permits(
            action,
            executor_is_dry_run=self.executor.dry_run,
            destructive_execution_allowed=self.destructive_execution_allowed,
        ):
            return blocked_action_result(action, self.executor.name, self.clock)
        result = self.executor.execute(action)
        if result.action_id != action.action_id or result.action is not action.action:
            raise ValueError("Remediation executor returned a mismatched action result")
        return result

    def process(self, event: SOCEvent) -> SOCEvent:
        planned_actions = self.determine_actions(event)
        results = [self._execute(action) for action in planned_actions]
        actions = [
            action.model_copy(update={"status": result.status})
            for action, result in zip(planned_actions, results, strict=True)
        ]
        enriched = event.model_copy(deep=True)
        enriched.remediation = RemediationMetadata(
            actions=actions,
            results=results,
            executor=self.executor.name,
            dry_run=self.executor.dry_run,
            policy_version=REMEDIATION_POLICY_VERSION,
            destructive_execution_allowed=self.destructive_execution_allowed,
            remediated_at=self.clock(),
        )
        return enriched.advance_stage(StageName.REMEDIATION, "remediation-agent")


def create_runtime_processor() -> RemediationProcessor:
    if REMEDIATION_EXECUTION_MODE != "dry_run":
        raise ValueError(
            "Only REMEDIATION_EXECUTION_MODE=dry_run is supported; "
            "no production executor is installed"
        )
    allow_destructive = _parse_bool(
        os.environ.get("REMEDIATION_ALLOW_DESTRUCTIVE", "false"),
        "REMEDIATION_ALLOW_DESTRUCTIVE",
    )
    return RemediationProcessor(
        executor=DryRunExecutor(),
        destructive_execution_allowed=allow_destructive,
    )


def determine_actions(event: SOCEvent) -> list[RemediationAction]:
    """Compatibility wrapper around the typed remediation processor."""

    return RemediationProcessor().determine_actions(event)


def process_event(event: SOCEvent) -> SOCEvent:
    """Compatibility wrapper for deterministic dry-run remediation."""

    return RemediationProcessor().process(event)


def remediation_log_record(event: SOCEvent) -> dict:
    return {
        "event_id": str(event.event_id),
        "incident_id": str(event.incident_id),
        "timestamp": (
            event.remediation.remediated_at.isoformat()
            if event.remediation.remediated_at
            else None
        ),
        "event": event.event,
        "severity": event.severity.value,
        "ip": event.source_ip,
        "user": event.user,
        "actions": [
            action.model_dump(mode="json") for action in event.remediation.actions
        ],
        "results": [
            result.model_dump(mode="json") for result in event.remediation.results
        ],
        "mitre": event.threat_intelligence.model_dump(mode="json"),
    }


def print_actions(event: SOCEvent) -> None:
    actions = event.remediation.actions
    print(f"\n{'=' * 50}")
    print(f"[{event.severity.value}] {event.event} | IP: {event.source_ip}")
    print(
        f"MITRE: {event.threat_intelligence.technique_id or 'N/A'} "
        f"{event.threat_intelligence.technique_name or ''} | "
        f"Tactic: {event.threat_intelligence.tactic or 'N/A'}"
    )
    print(f"Actions evaluated ({len(actions)}):")
    for action in actions:
        print(
            f"  [{action.status.value.upper()}] {action.action.value} "
            f"on {action.target}"
        )
        if action.argv_preview:
            print(f"     argv preview: {action.argv_preview!r}")
    print(f"{'=' * 50}\n", flush=True)


def main() -> None:
    from backend.database import init_db, persist_event
    from common.health import start_health_server
    from common.kafka import (
        consume_forever,
        create_consumer,
        create_producer,
        publish_event,
    )
    from common.pipeline import run_stage

    health = start_health_server("remediation-agent")
    try:
        processor = create_runtime_processor()
    except ValueError as exc:
        health.set_not_ready("remediation_configuration_error", error=str(exc))
        raise SystemExit(f"Remediation configuration error: {exc}") from exc

    consumer = create_consumer("threat_enriched_alerts", "soc-remediation")
    producer = create_producer()
    init_db()
    health.set_ready(
        processor=REMEDIATION_POLICY_VERSION,
        executor=processor.executor.name,
        dry_run=processor.executor.dry_run,
        destructive_execution_allowed=processor.destructive_execution_allowed,
    )
    print("Remediation Agent Running in policy-gated dry-run mode...\n")

    def handle(payload: dict) -> None:
        event = run_stage(
            payload,
            processor,
            persist_event,
            after_persist=lambda value: write_remediation_log(
                remediation_log_record(value)
            ),
            publish=lambda value: publish_event(
                producer,
                "remediation_actions",
                value,
            ),
        )
        print_actions(event)

    consume_forever(consumer, handle, "remediation-agent")


if __name__ == "__main__":
    main()
