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
import os
import sys
import subprocess
from datetime import datetime, timezone
from pathlib import Path

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from kafka import KafkaConsumer, KafkaProducer
from backend.database import init_db, persist_alert

# =========================================================
# REMEDIATION LOG FILE
# =========================================================

LOG_DIR  = _repo_root / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "remediation_actions.jsonl"   # one JSON object per line


def write_remediation_log(record: dict) -> None:
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

def determine_actions(alert: dict) -> list[dict]:
    """
    Return a list of remediation actions based on severity,
    recommended_action from threat intel, and available fields.
    """
    severity = alert.get("severity", "LOW")
    ip       = alert.get("ip") or "unknown"
    user     = alert.get("user") or "unknown"
    event    = alert.get("event", "unknown")
    actions  = []

    if severity == "CRITICAL":
        actions.append(_block_ip(ip))
        if user != "unknown":
            actions.append(_isolate_user(user))
        actions.append({
            "action": "ESCALATE_TO_ANALYST",
            "target": ip,
            "status": "triggered",
            "note":   f"CRITICAL alert for '{event}' — paging on-call analyst.",
        })

    elif severity == "HIGH":
        actions.append(_block_ip(ip))
        if user != "unknown":
            actions.append(_flag_user(user))

    elif severity == "MEDIUM":
        actions.append(_rate_limit_ip(ip))
        actions.append(_increase_monitoring(ip))

    else:  # LOW
        actions.append(_audit_log(event, ip))

    return actions


# =========================================================
# KAFKA SETUP
# =========================================================

_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")

consumer = KafkaConsumer(
    "threat_enriched_alerts",
    bootstrap_servers=_bootstrap,
    auto_offset_reset="earliest",
    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
)

producer = KafkaProducer(
    bootstrap_servers=_bootstrap,
    value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
)

print("Remediation Agent Running...\n")
init_db()

# =========================================================
# MAIN CONSUMER LOOP
# =========================================================

for message in consumer:

    alert   = message.value
    actions = determine_actions(alert)

    # Attach remediation actions to alert
    alert["remediation_actions"] = actions
    alert["remediation_count"]   = len(actions)
    alert["remediated_at"]       = datetime.now(timezone.utc).isoformat()

    # Persist enriched alert to PostgreSQL
    try:
        persist_alert(alert)
    except Exception as exc:
        print(json.dumps({"storage_error": str(exc)}), file=sys.stderr, flush=True)

    # Write structured remediation log
    log_record = {
        "timestamp": alert.get("remediated_at"),
        "event":     alert.get("event"),
        "severity":  alert.get("severity"),
        "ip":        alert.get("ip"),
        "user":      alert.get("user"),
        "actions":   actions,
        "mitre":     alert.get("mitre_attack"),
    }
    write_remediation_log(log_record)

    # Publish to Kafka for dashboard consumption
    producer.send("remediation_actions", alert)

    # Human-readable console output
    print(f"\n{'='*50}")
    print(f"[{alert.get('severity')}] {alert.get('event')} | IP: {alert.get('ip')}")
    print(f"MITRE: {alert.get('mitre_attack', 'N/A')} | Tactic: {alert.get('mitre_tactic', 'N/A')}")
    print(f"Actions taken ({len(actions)}):")
    for a in actions:
        print(f"  → [{a['status'].upper()}] {a['action']} on {a.get('target', 'N/A')}")
        if "command" in a:
            print(f"     cmd: {a['command']}")
    print(f"{'='*50}\n", flush=True)