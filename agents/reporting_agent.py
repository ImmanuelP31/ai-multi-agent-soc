"""Create idempotent incident reports from remediated canonical events."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Callable

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from common.events import (
    ReportingMetadata,
    SOCEvent,
    StageName,
)


REPORTS_DIR = _repo_root / "logs" / "reports"
SUMMARY_FILE = _repo_root / "logs" / "incident_summary.json"


def load_summary() -> dict:
    if SUMMARY_FILE.exists():
        try:
            summary = json.loads(SUMMARY_FILE.read_text())
            summary.setdefault("processed_incident_ids", [])
            return summary
        except (OSError, json.JSONDecodeError):
            pass
    return {
        "total_incidents": 0,
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "by_tactic": {},
        "top_ips": {},
        "processed_incident_ids": [],
        "last_updated": None,
    }


def save_summary(summary: dict) -> None:
    SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)
    summary["last_updated"] = datetime.now(timezone.utc).isoformat()
    SUMMARY_FILE.write_text(json.dumps(summary, indent=2, default=str))


def update_summary(summary: dict, report: dict) -> dict:
    incident_id = report["incident_id"]
    processed = summary.setdefault("processed_incident_ids", [])
    if incident_id in processed:
        return summary

    processed.append(incident_id)
    summary["total_incidents"] += 1
    severity = report.get("severity", "LOW")
    summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
    tactic = report.get("mitre_tactic", "Unknown") or "Unknown"
    summary["by_tactic"][tactic] = summary["by_tactic"].get(tactic, 0) + 1
    source_ip = report.get("ip") or "unknown"
    summary["top_ips"][source_ip] = summary["top_ips"].get(source_ip, 0) + 1
    return summary


class ReportingProcessor:
    """Build and idempotently store one report per stable incident identity."""

    def __init__(
        self,
        reports_dir: Path = REPORTS_DIR,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.reports_dir = reports_dir
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def process(self, event: SOCEvent) -> SOCEvent:
        enriched = event.model_copy(deep=True)
        enriched.reporting = ReportingMetadata(
            generated_at=self.clock(),
            report_path=str(self.reports_dir / f"{event.incident_id}.json"),
        )
        return enriched.advance_stage(StageName.REPORTING, "reporting-agent")

    def build_report(self, event: SOCEvent) -> dict:
        generated_at = event.reporting.generated_at or self.clock()
        return {
            "event_id": str(event.event_id),
            "incident_id": str(event.incident_id),
            "schema_version": event.schema_version,
            "generated_at": generated_at.isoformat(),
            "event": event.event,
            "severity": event.severity.value,
            "ip": event.source_ip,
            "user": event.user,
            "timestamp": event.observed_at.isoformat(),
            "detection_method": event.detection.method or "unknown",
            "anomaly_score": event.detection.anomaly_score,
            "investigation": event.investigation_metadata.summary,
            "investigation_method": event.investigation_metadata.method,
            "predicted_next_attack": (
                event.investigation_metadata.predicted_next_attack
            ),
            "lstm_confidence": event.investigation_metadata.confidence,
            "mitre_attack": event.threat_intelligence.mitre_attack,
            "mitre_tactic": event.threat_intelligence.mitre_tactic,
            "mitre_confidence": event.threat_intelligence.confidence,
            "recommended_action": event.threat_intelligence.recommended_action,
            "remediation_actions": [
                action.model_dump(mode="json")
                for action in event.remediation.actions
            ],
            "remediation_count": len(event.remediation.actions),
            "remediated_at": (
                event.remediation.remediated_at.isoformat()
                if event.remediation.remediated_at
                else None
            ),
            "stage": event.stage.model_dump(mode="json"),
        }

    def write_report(self, report: dict) -> Path:
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        filename = self.reports_dir / f"{report['incident_id']}.json"
        filename.write_text(json.dumps(report, indent=2, default=str))
        return filename


def process_event(event: SOCEvent) -> SOCEvent:
    """Compatibility wrapper for deterministic reporting processing."""

    return ReportingProcessor().process(event)


def build_report(event: SOCEvent) -> dict:
    return ReportingProcessor().build_report(event)


def write_report(report: dict) -> Path:
    return ReportingProcessor().write_report(report)


def print_report(report: dict) -> None:
    separator = "=" * 60
    print(f"\n{separator}")
    print(f"  INCIDENT REPORT  |  {report['incident_id']}")
    print(separator)
    print(f"  Event      : {report['event']}")
    print(f"  Severity   : {report['severity']}")
    print(f"  Source IP  : {report['ip'] or 'N/A'}")
    print(f"  User       : {report['user'] or 'N/A'}")
    print(f"  Detection  : {report['detection_method']}")
    print(f"  Prediction : {report['predicted_next_attack'] or 'unavailable'}")
    print(f"  MITRE      : {report['mitre_attack'] or 'N/A'}")
    print(f"  Tactic     : {report['mitre_tactic'] or 'N/A'}")
    print(f"  Actions    : {report['remediation_count']}")
    print(separator + "\n", flush=True)


def main() -> None:
    from backend.database import init_db, persist_event
    from common.kafka import consume_forever, create_consumer
    from common.pipeline import run_stage

    processor = ReportingProcessor()
    consumer = create_consumer("remediation_actions", "soc-reporting")
    init_db()
    summary = load_summary()
    print("Reporting Agent Running...\n")

    def handle(payload: dict) -> None:
        report = None
        report_path = None

        def store_outputs(event: SOCEvent) -> None:
            nonlocal report, report_path
            report = processor.build_report(event)
            report_path = processor.write_report(report)
            update_summary(summary, report)
            save_summary(summary)

        run_stage(
            payload,
            processor,
            persist_event,
            after_persist=store_outputs,
        )
        if report is None or report_path is None:
            raise RuntimeError("Reporting outputs were not generated")
        print_report(report)
        print(
            f"Report saved: {report_path.name} | "
            f"Total incidents: {summary['total_incidents']}",
            flush=True,
        )

    consume_forever(consumer, handle, "reporting-agent")


if __name__ == "__main__":
    main()
