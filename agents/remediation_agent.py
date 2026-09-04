"""
Remediation Agent
------------------
Consumes threat-enriched alerts and performs tiered automated response:

  CRITICAL  →  Block IP (iptables simulation) + isolate user + persist action
  HIGH      →  Block IP + flag user for review + persist action
  MEDIUM    →  Rate-limit IP + increase monitoring + persist action
  LOW       →  Log for audit + persist action

All actions are:
  - Persisted to PostgreSQL via the shared database module
  - Written to a structured JSON remediation log file
  - Published to `remediation_actions` Kafka topic for dashboard consumption

In a production environment, the _block_ip / _rate_limit calls would
invoke real firewall APIs (e.g. AWS WAF, iptables, Palo Alto PAN-OS).
The simulation layer makes the intent clear while keeping the code testable.
"""

import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from common.events import (
    RemediationAction,
    RemediationMetadata,
    SOCEvent,
    StageName,
)

# =========================================================
# REMEDIATION LOG FILE
# =========================================================

LOG_DIR  = _repo_root / "logs"
LOG_FILE = LOG_DIR / "remediation_actions.jsonl"   # one JSON object per line


def write_remediation_log(record: dict) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    event_id = record.get("event_id")
    if event_id and LOG_FILE.exists():
        with open(LOG_FILE) as existing:
            for line in existing:
                try:
                    if json.loads(line).get("event_id") == event_id:
                        return
                except json.JSONDecodeError:
                    continue
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(record, default=str) + "\n")


# =========================================================
# SIMULATED FIREWALL ACTIONS
# =========================================================

def _block_ip(ip: str) -> dict:
    """
    Simulate blocking an IP via iptables.
    In production: call iptables / AWS WAF / Palo Alto API here.
    """
    cmd = f"iptables -A INPUT -s {ip} -j DROP"
    return {
        "action":  "BLOCK_IP",
        "target":  ip,
        "command": cmd,
        "status":  "simulated",   # change to subprocess.run(cmd) in production
        "note":    "iptables rule simulated — replace with real firewall API call.",
    }


def _rate_limit_ip(ip: str) -> dict:
    """
    Simulate rate-limiting an IP (e.g. via iptables hashlimit).
    """
    cmd = (
        f"iptables -A INPUT -s {ip} -m hashlimit "
        f"--hashlimit-above 10/min --hashlimit-mode srcip -j DROP"
    )
    return {
        "action":  "RATE_LIMIT_IP",
        "target":  ip,
        "command": cmd,
        "status":  "simulated",
        "note":    "Rate-limit rule simulated.",
    }


def _isolate_user(user: str) -> dict:
    """
    Simulate disabling a user account (e.g. via usermod or AD API).
    """
    cmd = f"usermod --lock {user}"
    return {
        "action":  "ISOLATE_USER",
        "target":  user,
        "command": cmd,
        "status":  "simulated",
        "note":    "User lock simulated — replace with AD/LDAP disable call.",
    }


def _flag_user(user: str) -> dict:
    return {
        "action":  "FLAG_USER_FOR_REVIEW",
        "target":  user,
        "status":  "logged",
        "note":    "User flagged in SOC dashboard for analyst review.",
    }


def _increase_monitoring(ip: str) -> dict:
    return {
        "action":  "INCREASE_MONITORING",
        "target":  ip,
        "status":  "logged",
        "note":    "Elevated monitoring window opened for this IP.",
    }


def _audit_log(event: str, ip: str) -> dict:
    return {
        "action":  "AUDIT_LOG",
        "target":  ip,
        "event":   event,
        "status":  "logged",
        "note":    "Low-risk event recorded for audit trail.",
    }


# =========================================================
# TIERED RESPONSE ENGINE
# =========================================================

def _validated_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _validated_user(value: str | None) -> str | None:
    if value and re.fullmatch(r"[A-Za-z0-9_.@-]{1,255}", value):
        return value
    return None


def _manual_review(target: str | None, target_type: str) -> dict:
    return {
        "action": "MANUAL_REMEDIATION_REQUIRED",
        "target": target,
        "status": "skipped",
        "note": f"No command generated because {target_type} is missing or invalid.",
    }


class RemediationProcessor:
    """Build safe simulated actions without performing infrastructure I/O."""

    def __init__(
        self,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def determine_actions(self, event: SOCEvent) -> list[dict]:
        severity = event.severity.value
        valid_ip = _validated_ip(event.source_ip)
        valid_user = _validated_user(event.user)
        display_target = valid_ip or event.source_ip or "unknown"
        actions: list[dict] = []

        if severity == "CRITICAL":
            actions.append(
                _block_ip(valid_ip)
                if valid_ip
                else _manual_review(event.source_ip, "source IP")
            )
            if valid_user:
                actions.append(_isolate_user(valid_user))
            elif event.user:
                actions.append(_manual_review(event.user, "user identity"))
            actions.append(
                {
                    "action": "ESCALATE_TO_ANALYST",
                    "target": display_target,
                    "status": "triggered",
                    "note": (
                        f"CRITICAL alert for '{event.event}' - paging on-call analyst."
                    ),
                }
            )
        elif severity == "HIGH":
            actions.append(
                _block_ip(valid_ip)
                if valid_ip
                else _manual_review(event.source_ip, "source IP")
            )
            if valid_user:
                actions.append(_flag_user(valid_user))
            elif event.user:
                actions.append(_manual_review(event.user, "user identity"))
        elif severity == "MEDIUM":
            if valid_ip:
                actions.extend(
                    [_rate_limit_ip(valid_ip), _increase_monitoring(valid_ip)]
                )
            else:
                actions.append(_manual_review(event.source_ip, "source IP"))
        else:
            actions.append(_audit_log(event.event, display_target))

        return actions

    def process(self, event: SOCEvent) -> SOCEvent:
        actions = self.determine_actions(event)
        enriched = event.model_copy(deep=True)
        enriched.remediation = RemediationMetadata(
            actions=[RemediationAction.model_validate(action) for action in actions],
            remediated_at=self.clock(),
        )
        return enriched.advance_stage(StageName.REMEDIATION, "remediation-agent")


def determine_actions(event: SOCEvent) -> list[dict]:
    """Compatibility wrapper around the remediation processor."""

    return RemediationProcessor().determine_actions(event)


def process_event(event: SOCEvent) -> SOCEvent:
    """Compatibility wrapper for deterministic remediation processing."""

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
            action.model_dump(mode="json")
            for action in event.remediation.actions
        ],
        "mitre": event.threat_intelligence.mitre_attack,
    }


def print_actions(event: SOCEvent) -> None:
    actions = event.remediation.actions
    print(f"\n{'='*50}")
    print(f"[{event.severity.value}] {event.event} | IP: {event.source_ip}")
    print(
        f"MITRE: {event.threat_intelligence.mitre_attack or 'N/A'} | "
        f"Tactic: {event.threat_intelligence.mitre_tactic or 'N/A'}"
    )
    print(f"Actions taken ({len(actions)}):")
    for action in actions:
        print(
            f"  [{action.status.upper()}] {action.action} "
            f"on {action.target or 'N/A'}"
        )
        if action.command:
            print(f"     cmd: {action.command}")
    print(f"{'='*50}\n", flush=True)


def main() -> None:
    from backend.database import init_db, persist_event
    from common.kafka import (
        consume_forever,
        create_consumer,
        create_producer,
        publish_event,
    )
    from common.pipeline import run_stage

    processor = RemediationProcessor()
    consumer = create_consumer("threat_enriched_alerts", "soc-remediation")
    producer = create_producer()
    init_db()
    print("Remediation Agent Running...\n")

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
