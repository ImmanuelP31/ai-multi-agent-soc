"""
Reporting Agent
----------------
Consumes remediation_actions alerts and produces:

  1. A structured JSON incident report per alert (logs/reports/)
  2. A running summary file (logs/incident_summary.json) updated after every alert
  3. Console output with full incident details

Each report includes:
  - Incident metadata (ID, timestamp, severity, event, IP, user)
  - MITRE ATT&CK mapping + tactic
  - Investigation summary + LSTM prediction
  - All remediation actions taken
  - Recommended next steps from threat intel
"""

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from kafka import KafkaConsumer

# =========================================================
# OUTPUT DIRECTORIES
# =========================================================

REPORTS_DIR = _repo_root / "logs" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

SUMMARY_FILE = _repo_root / "logs" / "incident_summary.json"


def load_summary() -> dict:
    if SUMMARY_FILE.exists():
        try:
            return json.loads(SUMMARY_FILE.read_text())
        except Exception:
            pass
    return {
        "total_incidents":    0,
        "by_severity":        {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "by_tactic":          {},
        "top_ips":            {},
        "last_updated":       None,
    }


def save_summary(summary: dict) -> None:
    summary["last_updated"] = datetime.now(timezone.utc).isoformat()
    SUMMARY_FILE.write_text(json.dumps(summary, indent=2, default=str))


def update_summary(summary: dict, report: dict) -> dict:
    summary["total_incidents"] += 1

    sev = report.get("severity", "LOW")
    summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

    tactic = report.get("mitre_tactic", "Unknown")
    summary["by_tactic"][tactic] = summary["by_tactic"].get(tactic, 0) + 1

    ip = report.get("ip") or "unknown"
    summary["top_ips"][ip] = summary["top_ips"].get(ip, 0) + 1

    return summary


# =========================================================
# REPORT BUILDER
# =========================================================

def build_report(alert: dict) -> dict:
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    now         = datetime.now(timezone.utc).isoformat()

    return {
        "incident_id":          incident_id,
        "generated_at":         now,

        # Core fields
        "event":                alert.get("event", "unknown"),
        "severity":             alert.get("severity", "LOW"),
        "ip":                   alert.get("ip"),
        "user":                 alert.get("user"),
        "timestamp":            alert.get("timestamp", now),

        # Detection
        "detection_method":     alert.get("detection_method", "unknown"),
        "anomaly_score":        alert.get("anomaly_score"),

        # Investigation
        "investigation":        alert.get("investigation"),
        "investigation_method": alert.get("investigation_method"),
        "predicted_next_attack":alert.get("predicted_next_attack"),
        "lstm_confidence":      alert.get("confidence"),

        # Threat Intelligence
        "mitre_attack":         alert.get("mitre_attack"),
        "mitre_tactic":         alert.get("mitre_tactic"),
        "mitre_confidence":     alert.get("mitre_confidence"),
        "recommended_action":   alert.get("recommended_action"),

        # Remediation
        "remediation_actions":  alert.get("remediation_actions", []),
        "remediation_count":    alert.get("remediation_count", 0),
        "remediated_at":        alert.get("remediated_at"),
    }


def write_report(report: dict) -> Path:
    filename = REPORTS_DIR / f"{report['incident_id']}.json"
    filename.write_text(json.dumps(report, indent=2, default=str))
    return filename


def print_report(report: dict) -> None:
    sep = "=" * 60
    print(f"\n{sep}")
    print(f"  INCIDENT REPORT  |  {report['incident_id']}")
    print(sep)
    print(f"  Timestamp  : {report['generated_at']}")
    print(f"  Event      : {report['event']}")
    print(f"  Severity   : {report['severity']}")
    print(f"  Source IP  : {report['ip'] or 'N/A'}")
    print(f"  User       : {report['user'] or 'N/A'}")
    print(f"\n  [Detection]")
    print(f"  Method     : {report['detection_method']}")
    if report['anomaly_score'] is not None:
        print(f"  Anomaly Sc.: {report['anomaly_score']}")
    print(f"\n  [Investigation]")
    print(f"  {report['investigation']}")
    if report['predicted_next_attack']:
        print(f"  LSTM Pred  : {report['predicted_next_attack']} ({report['lstm_confidence'] * 100:.1f}% conf)" if report['lstm_confidence'] else f"  LSTM Pred  : {report['predicted_next_attack']}")
    print(f"\n  [Threat Intel]")
    print(f"  MITRE      : {report['mitre_attack'] or 'N/A'}")
    print(f"  Tactic     : {report['mitre_tactic'] or 'N/A'}")
    print(f"  Action     : {report['recommended_action'] or 'N/A'}")
    print(f"\n  [Remediation — {report['remediation_count']} action(s)]")
    for a in report["remediation_actions"]:
        print(f"  → {a['action']} on {a.get('target', 'N/A')} [{a['status'].upper()}]")
    print(sep + "\n", flush=True)


# =========================================================
# KAFKA SETUP
# =========================================================

_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")

consumer = KafkaConsumer(
    "remediation_actions",
    bootstrap_servers=_bootstrap,
    auto_offset_reset="earliest",
    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
)

print("Reporting Agent Running...\n")

summary = load_summary()

# =========================================================
# MAIN CONSUMER LOOP
# =========================================================

for message in consumer:

    alert  = message.value
    report = build_report(alert)

    # Write JSON report file
    report_path = write_report(report)

    # Update and save running summary
    summary = update_summary(summary, report)
    save_summary(summary)

    # Print to console
    print_report(report)

    print(
        f"📄 Report saved → {report_path.name} "
        f"| Total incidents: {summary['total_incidents']}",
        flush=True,
    )