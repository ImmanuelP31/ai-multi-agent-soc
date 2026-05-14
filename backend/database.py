"""PostgreSQL persistence for SOC alerts (shared with agents and API)."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Integer, String, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class SocAlert(Base):
    """
    Central SOC incident table.

    Stores:
    - raw alerts
    - sequence correlations
    - investigations
    - threat intel enrichments
    """

    __tablename__ = "soc_alerts"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    event: Mapped[str] = mapped_column(
        String(255)
    )

    severity: Mapped[str] = mapped_column(
        String(64)
    )

    ip: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True
    )

    user: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True
    )

    investigation: Mapped[Optional[str]] = mapped_column(
        String(1000),
        nullable=True
    )

    mitre_attack: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True
    )

    predicted_next_attack: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True
    )

    confidence: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True
    )

    agent_source: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True)
    )


def get_database_url() -> str:
    return os.environ.get(
        "DATABASE_URL",
        "postgresql://socuser:socpass@localhost:5432/socdb",
    )


_engine = None
SessionLocal = None


def init_engine():
    global _engine, SessionLocal
    if _engine is None:
        _engine = create_engine(get_database_url(), pool_pre_ping=True)
        SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)
    return _engine


def init_db() -> None:
    """Create tables if they do not exist."""
    engine = init_engine()
    Base.metadata.create_all(bind=_engine)
    ensure_soc_alert_schema(engine)


def ensure_soc_alert_schema(engine) -> None:
    """Add columns introduced after an existing database was first created."""

    inspector = inspect(engine)
    if not inspector.has_table(SocAlert.__tablename__):
        return

    existing_columns = {
        column["name"]
        for column in inspector.get_columns(SocAlert.__tablename__)
    }

    expected_columns = {
        "ip": "VARCHAR(64)",
        "user": "VARCHAR(255)",
        "investigation": "VARCHAR(1000)",
        "mitre_attack": "VARCHAR(255)",
        "predicted_next_attack": "VARCHAR(255)",
        "confidence": "VARCHAR(64)",
        "agent_source": "VARCHAR(128)",
    }

    missing_columns = [
        (name, column_type)
        for name, column_type in expected_columns.items()
        if name not in existing_columns
    ]

    if not missing_columns:
        return

    with engine.begin() as connection:
        for name, column_type in missing_columns:
            quoted_name = f'"{name}"' if name == "user" else name
            connection.execute(
                text(
                    f"ALTER TABLE {SocAlert.__tablename__} "
                    f"ADD COLUMN {quoted_name} {column_type}"
                )
            )


def timestamp_from_alert(alert: dict) -> datetime:
    ts = alert.get("timestamp")
    if ts is None:
        return datetime.now(timezone.utc)
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    return datetime.now(timezone.utc)


def persist_alert(alert: dict) -> None:
    """
    Persist SOC alerts into PostgreSQL.
    """

    init_engine()

    session = SessionLocal()

    try:

        row = SocAlert(
            event=alert.get("event", "unknown"),

            severity=alert.get(
                "severity",
                "LOW"
            ),

            ip=alert.get("ip"),

            user=alert.get("user"),

            investigation=alert.get(
                "investigation"
            ),

            mitre_attack=alert.get(
                "mitre_attack"
            ),

            predicted_next_attack=alert.get(
                "predicted_next_attack"
            ),

            confidence=str(
                alert.get("confidence")
            ) if alert.get("confidence") else None,

            agent_source=alert.get(
                "agent_source"
            ),

            timestamp=timestamp_from_alert(
                alert
            ),
        )

        session.add(row)

        session.commit()

    except Exception:

        session.rollback()

        raise

    finally:

        session.close()
        
