"""Typed remediation actions, policy checks, and safe execution contracts."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import ipaddress
from typing import Literal, Protocol
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field


REMEDIATION_POLICY_VERSION = "remediation-policy-v2"


class RemediationActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    RATE_LIMIT_IP = "RATE_LIMIT_IP"
    ISOLATE_USER = "ISOLATE_USER"
    FLAG_USER_FOR_REVIEW = "FLAG_USER_FOR_REVIEW"
    INCREASE_MONITORING = "INCREASE_MONITORING"
    AUDIT_LOG = "AUDIT_LOG"
    ESCALATE_TO_ANALYST = "ESCALATE_TO_ANALYST"


class RemediationTargetType(str, Enum):
    IP = "ip"
    USER = "user"
    INCIDENT = "incident"


class RemediationTargetScope(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    NOT_APPLICABLE = "not_applicable"


class RemediationPolicyClass(str, Enum):
    AUTOMATIC_SAFE = "automatic_safe"
    REQUIRES_APPROVAL = "requires_approval"


class RemediationActionStatus(str, Enum):
    PLANNED = "planned"
    DRY_RUN = "dry_run"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    COMPLETED = "completed"
    FAILED = "failed"


class RemediationContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ValidatedIP(RemediationContract):
    value: str
    version: Literal[4, 6]
    scope: RemediationTargetScope


class RemediationAction(RemediationContract):
    action_id: UUID
    action: RemediationActionType
    target_type: RemediationTargetType
    target: str = Field(min_length=1, max_length=255)
    target_scope: RemediationTargetScope = RemediationTargetScope.NOT_APPLICABLE
    policy: RemediationPolicyClass
    status: RemediationActionStatus = RemediationActionStatus.PLANNED
    argv_preview: list[str] = Field(default_factory=list)
    note: str | None = None


class ActionResult(RemediationContract):
    action_id: UUID
    action: RemediationActionType
    status: RemediationActionStatus
    executor: str
    dry_run: bool
    processed_at: datetime
    detail: str


def stable_action_id(
    incident_id: UUID,
    action: RemediationActionType,
    target_type: RemediationTargetType,
    target: str,
) -> UUID:
    """Create replay-stable identity for one logical incident action."""

    return uuid5(incident_id, f"{action.value}:{target_type.value}:{target}")


def validate_ip_target(value: str | None) -> ValidatedIP | None:
    """Normalize actionable IPv4/IPv6 targets without accepting shell fragments."""

    if not value or value.strip().lower() == "unknown":
        return None
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return None

    if parsed.is_unspecified or parsed.is_loopback or parsed.is_link_local:
        return None
    if parsed.is_multicast:
        return None

    scope = (
        RemediationTargetScope.PRIVATE
        if parsed.is_private
        else RemediationTargetScope.PUBLIC
    )
    return ValidatedIP(value=str(parsed), version=parsed.version, scope=scope)


class RemediationPolicy:
    """Classify actions and gate non-dry-run destructive execution."""

    destructive_actions = frozenset(
        {
            RemediationActionType.BLOCK_IP,
            RemediationActionType.RATE_LIMIT_IP,
            RemediationActionType.ISOLATE_USER,
        }
    )

    def classify(self, action: RemediationActionType) -> RemediationPolicyClass:
        if action in self.destructive_actions:
            return RemediationPolicyClass.REQUIRES_APPROVAL
        return RemediationPolicyClass.AUTOMATIC_SAFE

    def permits(
        self,
        action: RemediationAction,
        *,
        executor_is_dry_run: bool,
        destructive_execution_allowed: bool,
    ) -> bool:
        expected_class = self.classify(action.action)
        if action.policy is not expected_class:
            return False
        if (
            not executor_is_dry_run
            and action.target_type is RemediationTargetType.IP
            and action.target_scope is RemediationTargetScope.PRIVATE
        ):
            return False
        return (
            executor_is_dry_run
            or expected_class is RemediationPolicyClass.AUTOMATIC_SAFE
            or destructive_execution_allowed
        )


class RemediationExecutor(Protocol):
    name: str
    dry_run: bool

    def execute(self, action: RemediationAction) -> ActionResult:
        """Execute or simulate one already validated and policy-approved action."""


class DryRunExecutor:
    """Default executor that records intent and never invokes a system command."""

    name = "dry-run"
    dry_run = True

    def __init__(self, clock=None) -> None:
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def execute(self, action: RemediationAction) -> ActionResult:
        return ActionResult(
            action_id=action.action_id,
            action=action.action,
            status=RemediationActionStatus.DRY_RUN,
            executor=self.name,
            dry_run=True,
            processed_at=self.clock(),
            detail="Validated action recorded; no external command was executed.",
        )


def blocked_action_result(
    action: RemediationAction,
    executor_name: str,
    clock=None,
) -> ActionResult:
    now = clock or (lambda: datetime.now(timezone.utc))
    return ActionResult(
        action_id=action.action_id,
        action=action.action,
        status=RemediationActionStatus.BLOCKED_BY_POLICY,
        executor=executor_name,
        dry_run=False,
        processed_at=now(),
        detail="Execution was blocked by remediation policy or missing approval.",
    )
