"""
backend/main.py
----------------
FastAPI backend for the AI SOC system.

Endpoints:
  GET  /                      → health check
  GET  /alerts                → last N alerts from PostgreSQL
  GET  /alerts/stats          → severity counts + top IPs for dashboard charts
  WS   /ws/live-alerts        → WebSocket stream; pushes every new alert in real time
"""

import asyncio
import json
import os
import threading
import sys
from pathlib import Path

import redis as redis_lib
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from kafka import KafkaConsumer
from sqlalchemy import func, text

# =========================================================
# LOCAL IMPORTS
# =========================================================

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.database import (
    init_db,
    SessionLocal,
    SocAlert,
    init_engine,
)

from backend.routes import alerts as alerts_router
from backend.routes import sequences as sequences_router

# =========================================================
# FASTAPI APP
# =========================================================

app = FastAPI(title="AI SOC Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# ROUTERS
# =========================================================

# Registers:
# /alerts/*
# /sequences/*
app.include_router(alerts_router.router)
app.include_router(sequences_router.router)

# =========================================================
# REDIS CONFIG
# =========================================================

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_CHANNEL = "live_alerts"

def get_redis() -> redis_lib.Redis:
    return redis_lib.Redis(
        host=REDIS_HOST,
        port=6379,
        decode_responses=True,
    )

# =========================================================
# KAFKA CONFIG
# =========================================================

KAFKA_BOOTSTRAP = os.environ.get(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9094"
)

# =========================================================
# KAFKA → REDIS BRIDGE
# =========================================================

def kafka_to_redis_bridge():
    """
    Background thread:
    Kafka consumer → Redis pub/sub
    """

    try:
        consumer = KafkaConsumer(
            "remediation_actions",
            bootstrap_servers=KAFKA_BOOTSTRAP,
            auto_offset_reset="latest",
            value_deserializer=lambda m: json.loads(
                m.decode("utf-8")
            ),
        )

        r = get_redis()

        print("Kafka→Redis bridge started")

        for message in consumer:
            alert = message.value

            r.publish(
                REDIS_CHANNEL,
                json.dumps(alert, default=str)
            )

    except Exception as e:
        print(f"Kafka→Redis bridge error: {e}")

# =========================================================
# STARTUP
# =========================================================

@app.on_event("startup")
def on_startup():
    """
    Initialize DB and start Kafka bridge thread.
    """

    init_db()

    t = threading.Thread(
        target=kafka_to_redis_bridge,
        daemon=True,
    )

    t.start()

# =========================================================
# WEBSOCKET — LIVE ALERTS
# =========================================================

@app.websocket("/ws/live-alerts")
async def websocket_endpoint(websocket: WebSocket):

    await websocket.accept()

    r = get_redis()

    pubsub = r.pubsub()

    pubsub.subscribe(REDIS_CHANNEL)

    try:
        loop = asyncio.get_event_loop()

        while True:

            message = await loop.run_in_executor(
                None,
                lambda: pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=1.0,
                ),
            )

            if (
                message
                and message.get("type") == "message"
            ):
                await websocket.send_text(
                    message["data"]
                )

    except WebSocketDisconnect:
        # Client disconnected cleanly
        pass

    except Exception as e:
        print(f"WebSocket error: {e}")

        try:
            await websocket.close()
        except:
            pass

    finally:
        pubsub.unsubscribe(REDIS_CHANNEL)
        pubsub.close()

# =========================================================
# REST — ALERTS
# =========================================================

@app.get("/alerts")
def get_alerts(limit: int = 50, skip: int = 0):

    limit = min(limit, 500)

    init_engine()

    session = SessionLocal()

    try:

        rows = (
            session.query(SocAlert)
            .order_by(SocAlert.id.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

        return [
            {
                "id": r.id,
                "event": r.event,
                "severity": r.severity,
                "ip": r.ip,
                "user": r.user,
                "investigation": r.investigation,
                "mitre_attack": r.mitre_attack,
                "predicted_next_attack": r.predicted_next_attack,
                "confidence": r.confidence,
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
# REST — STATS
# =========================================================

@app.get("/alerts/stats")
def get_stats():

    init_engine()

    session = SessionLocal()

    try:

        total = (
            session.query(func.count(SocAlert.id))
            .scalar() or 0
        )

        severity_rows = (
            session.query(
                SocAlert.severity,
                func.count(SocAlert.id),
            )
            .group_by(SocAlert.severity)
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
                "severity": k,
                "count": v,
            }
            for k, v in severity_counts.items()
        ]

        top_ips_rows = (
            session.query(
                SocAlert.ip,
                func.count(SocAlert.id).label("count"),
            )
            .filter(SocAlert.ip.isnot(None))
            .group_by(SocAlert.ip)
            .order_by(text("count DESC"))
            .limit(5)
            .all()
        )

        top_ips = [
            {
                "ip": ip,
                "count": cnt,
            }
            for ip, cnt in top_ips_rows
        ]

        malware_count = (
            session.query(func.count(SocAlert.id))
            .filter(
                SocAlert.event == "malware_detected"
            )
            .scalar() or 0
        )

        critical_count = severity_counts.get(
            "CRITICAL",
            0,
        )

        return {
            "total_alerts": total,
            "severity_counts": severity_counts,
            "severity_chart": severity_chart,
            "top_ips": top_ips,
            "critical_count": critical_count,
            "malware_count": malware_count,
        }

    finally:
        session.close()

# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/")
def home():

    return {
        "status": "ok",
        "message": "AI SOC Backend Running",
    }