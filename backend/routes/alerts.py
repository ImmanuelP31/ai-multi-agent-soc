from fastapi import APIRouter
from sqlalchemy import text
from backend.database import init_engine

router = APIRouter(prefix="/alerts", tags=["Alerts"])

# FIX: reuse the shared engine from database.py instead of creating a new one
# with a mismatched password ("socpassword" vs "socpass" in docker-compose).
def get_engine():
    return init_engine()


@router.get("/")
def get_alerts():
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(
            text("""
                SELECT *
                FROM soc_alerts
                ORDER BY timestamp DESC
                LIMIT 100
            """)
        )
        alerts = []
        for row in result:
            alerts.append(dict(row._mapping))
        return alerts


# FIX: add /alerts/stats endpoint — StatsCards and SeverityChart both call this
# and were getting 404s, causing "Could not load stats" errors in the UI.
@router.get("/stats")
def get_stats():
    engine = get_engine()
    with engine.connect() as conn:
        # Total alerts
        total_row = conn.execute(
            text("SELECT COUNT(*) AS cnt FROM soc_alerts")
        ).fetchone()
        total_alerts = total_row.cnt if total_row else 0

        # Critical count
        critical_row = conn.execute(
            text("SELECT COUNT(*) AS cnt FROM soc_alerts WHERE severity = 'CRITICAL'")
        ).fetchone()
        critical_count = critical_row.cnt if critical_row else 0

        # Malware events (events containing "malware")
        malware_row = conn.execute(
            text("SELECT COUNT(*) AS cnt FROM soc_alerts WHERE LOWER(event) LIKE '%malware%'")
        ).fetchone()
        malware_count = malware_row.cnt if malware_row else 0

        # Severity chart data for the bar chart
        severity_result = conn.execute(
            text("""
                SELECT severity, COUNT(*) AS count
                FROM soc_alerts
                GROUP BY severity
                ORDER BY CASE severity
                    WHEN 'LOW'      THEN 1
                    WHEN 'MEDIUM'   THEN 2
                    WHEN 'HIGH'     THEN 3
                    WHEN 'CRITICAL' THEN 4
                    ELSE 5
                END
            """)
        )
        severity_chart = [
            {"severity": row.severity, "count": row.count}
            for row in severity_result
        ]

        return {
            "total_alerts": total_alerts,
            "critical_count": critical_count,
            "malware_count": malware_count,
            "severity_chart": severity_chart,
        }