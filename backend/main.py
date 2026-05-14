"""
backend/main.py
AI SOC Backend
"""

import asyncio
import json
import os
import threading
import sys
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from kafka import KafkaConsumer
from sqlalchemy import func

# =========================================================
# LOCAL IMPORTS
# =========================================================

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.database import (
    init_db,
    SessionLocal,
    SocAlert,
)

from backend.routes import alerts as alerts_router
from backend.routes import sequences as sequences_router

# =========================================================
# OPTIONAL REDIS IMPORT
# =========================================================

try:
    import redis as redis_lib
except Exception:
    redis_lib = None

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

app.include_router(alerts_router.router)
app.include_router(sequences_router.router)

# =========================================================
# CONFIG
# =========================================================

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))

KAFKA_BOOTSTRAP = os.environ.get(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9094"
)

REDIS_CHANNEL = "live_alerts"

# =========================================================
# REDIS
# =========================================================

def get_redis():
    """
    Lazy Redis connection.
    Never crashes backend startup.
    """

    if redis_lib is None:
        return None

    try:
        r = redis_lib.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            decode_responses=True,
            socket_connect_timeout=2,
        )

        r.ping()

        return r

    except Exception as e:
        print(f"[REDIS] unavailable: {e}")
        return None

# =========================================================
# KAFKA → REDIS BRIDGE
# =========================================================

def kafka_to_redis_bridge():

    try:

        consumer = KafkaConsumer(
            "remediation_actions",
            bootstrap_servers=KAFKA_BOOTSTRAP,
            auto_offset_reset="latest",
            value_deserializer=lambda m: json.loads(
                m.decode("utf-8")
            ),
        )

        print("[KAFKA] bridge connected")

        for message in consumer:

            alert = message.value

            r = get_redis()

            if not r:
                continue

            try:

                r.publish(
                    REDIS_CHANNEL,
                    json.dumps(alert, default=str)
                )

            except Exception as e:
                print(f"[REDIS] publish failed: {e}")

    except Exception as e:
        print(f"[KAFKA] bridge failed: {e}")

# =========================================================
# STARTUP
# =========================================================

@app.on_event("startup")
def startup():

    print("[STARTUP] Initializing database")

    init_db()

    print("[STARTUP] Starting Kafka bridge thread")

    t = threading.Thread(
        target=kafka_to_redis_bridge,
        daemon=True,
    )

    t.start()

# =========================================================
# WEBSOCKET
# =========================================================

@app.websocket("/ws/live-alerts")
async def websocket_endpoint(websocket: WebSocket):

    await websocket.accept()

    r = get_redis()

    if not r:
        await websocket.send_text(json.dumps({
            "event": "system",
            "severity": "LOW",
            "message": "Redis unavailable"
        }))

        await websocket.close()

        return

    pubsub = r.pubsub()

    pubsub.subscribe(REDIS_CHANNEL)

    print("[WS] client connected")

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

            await asyncio.sleep(0.05)

    except WebSocketDisconnect:

        print("[WS] client disconnected")

    except Exception as e:

        print(f"[WS] error: {e}")

    finally:

        try:
            pubsub.unsubscribe(REDIS_CHANNEL)
            pubsub.close()
        except:
            pass

# =========================================================
# REST
# =========================================================

@app.get("/")
def home():

    return {
        "status": "ok",
        "message": "AI SOC Backend Running",
    }

# =========================================================
# FALLBACK STATS
# =========================================================

@app.get("/health")
def health():

    return {
        "backend": "healthy",
        "redis": bool(get_redis()),
    }