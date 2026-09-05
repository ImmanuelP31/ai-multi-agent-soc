"""Small in-process health server for Kafka agent containers."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
from typing import Any


class ServiceHealth:
    """Thread-safe liveness/readiness state exposed over HTTP."""

    def __init__(self, service: str) -> None:
        self.service = service
        self._lock = threading.Lock()
        self._ready = False
        self._details: dict[str, Any] = {"status": "starting"}

    def set_ready(self, **details: Any) -> None:
        with self._lock:
            self._ready = True
            self._details = {"status": "ready", **details}

    def set_not_ready(self, reason: str, **details: Any) -> None:
        with self._lock:
            self._ready = False
            self._details = {"status": "not_ready", "reason": reason, **details}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "service": self.service,
                "live": True,
                "ready": self._ready,
                **self._details,
            }


def _handler_for(state: ServiceHealth):
    class HealthHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path == "/health/live":
                payload = {"service": state.service, "live": True}
                status_code = 200
            elif self.path == "/health/ready":
                payload = state.snapshot()
                status_code = 200 if payload["ready"] else 503
            else:
                payload = {"detail": "not found"}
                status_code = 404

            body = json.dumps(payload).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *args: Any) -> None:
            return

    return HealthHandler


def start_health_server(
    service: str,
    *,
    port: int | None = None,
) -> ServiceHealth:
    """Start a daemon health server and return its mutable readiness state."""

    health = ServiceHealth(service)
    health_port = port or int(os.environ.get("AGENT_HEALTH_PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", health_port), _handler_for(health))
    thread = threading.Thread(
        target=server.serve_forever,
        name=f"{service}-health",
        daemon=True,
    )
    thread.start()
    return health
