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
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from fastapi import FastAPI, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

# =========================================================
# LOCAL IMPORTS
# =========================================================

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.database import (
    init_db,
)

from backend.routes import alerts as alerts_router
from common.events import deserialize_event
from common.kafka import SOC_TOPICS, check_kafka, consume_forever, create_consumer

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


def configured_cors_origins() -> list[str]:
    raw_origins = os.environ.get(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    )
    origins = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]
    if not origins:
        raise ValueError("CORS_ALLOWED_ORIGINS must contain at least one origin")
    if "*" in origins:
        raise ValueError("Wildcard CORS is not allowed with credentialed requests")
    return origins


app.add_middleware(
    CORSMiddleware,
    allow_origins=configured_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# ROUTERS
# =========================================================

app.include_router(alerts_router.router)

# =========================================================
# CONFIG
# =========================================================

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))

REDIS_CHANNEL = "live_alerts"
PIPELINE_HEALTH_URLS = os.environ.get("PIPELINE_HEALTH_URLS", "")

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

        consumer = create_consumer(
            "remediation_actions",
            "soc-live-alert-bridge",
            offset_reset="latest",
        )

        print("[KAFKA] bridge connected")

        def handle(payload: dict) -> None:
            event = deserialize_event(payload)
            r = get_redis()
            if not r:
                raise ConnectionError("Redis unavailable")
            r.publish(
                REDIS_CHANNEL,
                json.dumps(event.to_message(), default=str)
            )

        consume_forever(consumer, handle, "live-alert-bridge")

    except Exception as e:
        print(f"[KAFKA] bridge failed: {e}")

# =========================================================
# STARTUP
# =========================================================

@app.on_event("startup")
def startup():

    print("[STARTUP] Verifying migrated database connection")

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
        except Exception:
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
def health(response: Response):
    checks: dict[str, dict] = {}

    try:
        init_db()
        checks["database"] = {"ready": True}
    except Exception as exc:
        checks["database"] = {"ready": False, "detail": str(exc)}

    redis_client = get_redis()
    checks["redis"] = {"ready": redis_client is not None}

    try:
        topics = check_kafka()
        missing_topics = sorted(set(SOC_TOPICS) - set(topics))
        checks["kafka"] = {
            "ready": not missing_topics,
            "topics": topics,
            "missing_topics": missing_topics,
        }
    except Exception as exc:
        checks["kafka"] = {"ready": False, "detail": str(exc)}

    for configured in PIPELINE_HEALTH_URLS.split(","):
        configured = configured.strip()
        if not configured:
            continue
        name, separator, url = configured.partition("=")
        if not separator or not name.strip() or not url.strip():
            checks["pipeline_configuration"] = {
                "ready": False,
                "detail": f"Invalid pipeline health entry: {configured!r}",
            }
            continue
        try:
            with urlopen(url.strip(), timeout=2) as result:  # noqa: S310
                payload = json.loads(result.read().decode("utf-8"))
            checks[name.strip()] = {
                "ready": bool(payload.get("ready")),
                **payload,
            }
        except (HTTPError, URLError, TimeoutError, ValueError) as exc:
            checks[name.strip()] = {"ready": False, "detail": str(exc)}

    is_ready = all(check.get("ready", False) for check in checks.values())
    if not is_ready:
        response.status_code = 503
    return {
        "status": "ready" if is_ready else "not_ready",
        "process": "running",
        "checks": checks,
    }


@app.get("/health/live")
def liveness():
    return {"status": "alive", "process": "running"}
