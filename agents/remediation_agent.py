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

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from backend.database import init_db, persist_event
from common.events import (
    RemediationAction,
    RemediationMetadata,
    SOCEvent,
    StageName,
    deserialize_event,
)
from common.kafka import consume_forever, create_consumer, create_producer, publish_event

# =========================================================
# REMEDIATION LOG FILE
# =========================================================

LOG_DIR  = _repo_root / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "remediation_actions.jsonl"   # one JSON object per line


def write_remediation_log(record: dict) -> None:
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

def determine_actions(event: SOCEvent) -> list[dict]:
    """
    Return a list of remediation actions based on severity,
    recommended_action from threat intel, and available fields.
    """
    severity = event.severity.value
    ip       = event.source_ip or "unknown"
    user     = event.user or "unknown"
    event_name = event.event
    actions  = []

    if severity == "CRITICAL":
        actions.append(_block_ip(ip))
        if user != "unknown":
            actions.append(_isolate_user(user))
        actions.append({
            "action": "ESCALATE_TO_ANALYST",
            "target": ip,
            "status": "triggered",
            "note":   f"CRITICAL alert for '{event_name}' — paging on-call analyst.",
        })

    elif severity == "HIGH":
        actions.append(_block_ip(ip))
        if user != "unknown":
            actions.append(_flag_user(user))

    elif severity == "MEDIUM":
        actions.append(_rate_limit_ip(ip))
        actions.append(_increase_monitoring(ip))

    else:  # LOW
        actions.append(_audit_log(event_name, ip))

    return actions


def process_event(event: SOCEvent) -> SOCEvent:
    """Attach simulated response actions while preserving identity."""

    actions = determine_actions(event)
    enriched = event.model_copy(deep=True)
    enriched.remediation = RemediationMetadata(
        actions=[RemediationAction.model_validate(action) for action in actions],
        remediated_at=datetime.now(timezone.utc),
    )
    return enriched.advance_stage(StageName.REMEDIATION, "remediation-agent")


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
    consumer = create_consumer("threat_enriched_alerts", "soc-remediation")
    producer = create_producer()
    init_db()
    print("Remediation Agent Running...\n")

    def handle(payload: dict) -> None:
        event = process_event(deserialize_event(payload))
        persist_event(event)
        write_remediation_log(remediation_log_record(event))
        publish_event(producer, "remediation_actions", event)
        print_actions(event)

    consume_forever(consumer, handle, "remediation-agent")


if __name__ == "__main__":
    main()
