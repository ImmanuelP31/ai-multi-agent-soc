from fastapi import APIRouter
from sqlalchemy import func
from backend import database as db

router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"]
)

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
            session.query(db.SocAlert)
            .order_by(db.SocAlert.id.desc())
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
                "source_ip": r.source_ip or r.ip,
                "ip": r.source_ip or r.ip,
                "user": r.user,
                "detection": r.detection_metadata,
                "detection_method": (
                    (r.detection_metadata or {}).get("method")
                ),
                "anomaly_score": (
                    (r.detection_metadata or {}).get("anomaly_score")
                ),
                "detection_model_status": (
                    (r.detection_metadata or {}).get("model_status")
                ),
                "investigation": r.investigation,
                "investigation_method": r.investigation_method,
                "mitre_attack": r.mitre_attack,
                "predicted_next_attack": r.predicted_next_attack,
                "confidence": r.confidence,
                "lstm_status": r.lstm_status,
                "current_stage": r.current_stage,
                "processing_version": r.processing_version,
                "last_updated_at": (
                    r.last_updated_at.isoformat()
                    if r.last_updated_at else None
                ),
                "timestamp": (
                    r.timestamp.isoformat()
                    if r.timestamp else None
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
            session.query(func.count(db.SocAlert.id))
            .scalar() or 0
        )

        severity_rows = (
            session.query(
                db.SocAlert.severity,
                func.count(db.SocAlert.id),
            )
            .group_by(db.SocAlert.severity)
            .all()
        )

        severity_counts = {
            sev: cnt
            for sev, cnt in severity_rows
        }

        for level in (
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        ):
            severity_counts.setdefault(level, 0)

        severity_chart = [
            {
                "severity": level,
                "count": severity_counts[level],
            }
            for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        ]

        malware_count = (
            session.query(func.count(db.SocAlert.id))
            .filter(
                db.SocAlert.event.ilike("%malware%")
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
