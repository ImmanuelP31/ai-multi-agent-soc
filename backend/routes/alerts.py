from fastapi import APIRouter
from sqlalchemy import func
from backend import database as db
from common.events import Severity

router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"]
)


def combined_mitre_technique(row: db.Incident) -> str | None:
    if row.mitre_technique_id and row.mitre_technique_name:
        return f"{row.mitre_technique_id} - {row.mitre_technique_name}"
    return row.mitre_technique_id or row.mitre_technique_name

# =========================================================
# ALERTS
# =========================================================

@router.get("/")
def get_alerts(limit: int = 100, skip: int = 0):

    limit = min(limit, 500)

    db.init_engine()

    session = db.SessionLocal()

    try:

        rows = (
            session.query(db.Incident)
            .order_by(db.Incident.observed_at.desc(), db.Incident.id.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

        return [
            {
                "id": r.id,
                "event_id": r.event_id,
                "incident_id": r.incident_id,
                "schema_version": r.schema_version,
                "event": r.event,
                "severity": r.severity,
                "source_ip": r.source_ip,
                "ip": r.source_ip,
                "user": r.user,
                "detection": r.detection_metadata,
                "detection_method": r.detection_method,
                "anomaly_score": r.anomaly_score,
                "detection_model_status": (
                    (r.detection_metadata or {}).get("model_status")
                ),
                "investigation": r.investigation,
                "investigation_metadata": r.investigation_metadata,
                "investigation_method": r.investigation_method,
                "mitre_attack": combined_mitre_technique(r),
                "mitre_technique_id": r.mitre_technique_id,
                "mitre_technique_name": r.mitre_technique_name,
                "mitre_tactic": r.mitre_tactic,
                "mitre_confidence": r.mitre_confidence,
                "mitre_mapping_version": r.mitre_mapping_version,
                "mitre_match_type": r.threat_intelligence_method,
                "mitre_evidence": r.mitre_evidence,
                "recommended_action": r.recommended_action,
                "threat_intel_method": r.threat_intelligence_method,
                "threat_intelligence": r.threat_intelligence_metadata or {},
                "predicted_next_attack": r.predicted_next_attack,
                "confidence": r.prediction_confidence,
                "lstm_status": r.sequence_model_status,
                "top_predictions": (
                    (r.investigation_metadata or {}).get("top_predictions", [])
                ),
                "sequence_length_used": (
                    (r.investigation_metadata or {}).get("sequence_length_used")
                ),
                "sequence_model_version": (
                    (r.investigation_metadata or {}).get("model_version")
                ),
                "prediction_timestamp": (
                    (r.investigation_metadata or {}).get("prediction_timestamp")
                ),
                "current_stage": r.current_stage,
                "processing_version": r.processing_version,
                "remediation_actions": r.remediation_actions or [],
                "remediation_metadata": r.remediation_metadata or {},
                "created_at": r.created_at.isoformat(),
                "last_updated_at": (
                    r.updated_at.isoformat()
                    if r.updated_at else None
                ),
                "timestamp": (
                    r.observed_at.isoformat()
                    if r.observed_at else None
                ),
            }
            for r in rows
        ]

    finally:
        session.close()

# =========================================================
# STATS
# =========================================================

@router.get("/stats")
def get_stats():

    db.init_engine()

    session = db.SessionLocal()

    try:

        total = (
            session.query(func.count(db.Incident.id))
            .scalar() or 0
        )

        severity_rows = (
            session.query(
                db.Incident.severity,
                func.count(db.Incident.id),
            )
            .group_by(db.Incident.severity)
            .all()
        )

        severity_counts = {
            sev: cnt
            for sev, cnt in severity_rows
        }

        severity_levels = [
            severity.value for severity in Severity if severity is not Severity.UNKNOWN
        ]
        for level in severity_levels:
            severity_counts.setdefault(level, 0)

        severity_chart = [
            {
                "severity": level,
                "count": severity_counts[level],
            }
            for level in severity_levels
        ]

        malware_count = (
            session.query(func.count(db.Incident.id))
            .filter(
                db.Incident.event.ilike("%malware%")
            )
            .scalar() or 0
        )

        critical_count = severity_counts.get(
            "CRITICAL",
            0,
        )

        return {
            "total_alerts": total,
            "critical_count": critical_count,
            "malware_count": malware_count,
            "severity_chart": severity_chart,
            "severity_counts": severity_counts,
        }

    finally:
        session.close()
