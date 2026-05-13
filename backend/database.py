"""PostgreSQL persistence for SOC alerts (shared with agents and API)."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class SocAlert(Base):
    """One row per detection alert — historical analysis, querying, dashboards."""

    __tablename__ = "soc_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(64))
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))


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
    init_engine()
    Base.metadata.create_all(bind=_engine)


def timestamp_from_alert(alert: dict) -> datetime:
    ts = alert.get("timestamp")
    if ts is None:
        return datetime.now(timezone.utc)
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    return datetime.now(timezone.utc)


def persist_alert(alert: dict) -> None:
    """Insert one alert row."""
    init_engine()
    session = SessionLocal()
    try:
        row = SocAlert(
            event=alert["event"],
            severity=alert["severity"],
            ip=alert.get("ip"),
            timestamp=timestamp_from_alert(alert),
        )
        session.add(row)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
