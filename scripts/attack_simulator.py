"""Continuously publish synthetic events using the canonical SOC contract."""

from __future__ import annotations

import json
from pathlib import Path
import random
import sys
import time

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from common.events import GroundTruthMetadata, SOCEvent
from common.kafka import create_producer, publish_event


ATTACK_TYPES = [
    "failed_login",
    "port_scan",
    "malware_detected",
    "ddos_attempt",
    "unauthorized_access",
    "privilege_escalation",
]

IPS = [
    "192.168.1.10",
    "192.168.1.20",
    "10.0.0.5",
    "172.16.0.3",
    "45.33.12.99",
]

USERS = ["admin", "guest", "root", "test_user"]


def create_attack() -> SOCEvent:
    attack_type = random.choice(ATTACK_TYPES)
    return SOCEvent.create_ingested(
        event=attack_type,
        source_ip=random.choice(IPS),
        user=random.choice(USERS),
        ground_truth=GroundTruthMetadata(
            synthetic=True,
            attack_label=attack_type,
            generator="scripts/attack_simulator.py",
        ),
    )


def main() -> None:
    producer = create_producer()
    while True:
        event = create_attack()
        publish_event(producer, "soc_logs", event)
        print(f"Generated Attack: {json.dumps(event.to_message())}", flush=True)
        time.sleep(2)


if __name__ == "__main__":
    main()
