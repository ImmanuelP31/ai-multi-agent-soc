from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import random

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.websocket("/ws/live-alerts")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    while True:
        fake_alert = {
            "event": random.choice([
                "Port Scan",
                "Brute Force",
                "Privilege Escalation",
                "Data Exfiltration"
            ]),
            "severity": random.choice([
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            ]),
            "ip": f"192.168.1.{random.randint(1,255)}"
        }

        await websocket.send_json(fake_alert)

        await asyncio.sleep(2)