from fastapi import APIRouter
from sqlalchemy import create_engine, text
import os

router = APIRouter(prefix="/alerts", tags=["Alerts"])

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://socuser:socpassword@localhost:5432/socdb"
)

engine = create_engine(DATABASE_URL)


@router.get("/")
def get_alerts():

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