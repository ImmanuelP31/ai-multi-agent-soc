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

from common.events import GroundTruthMetadata, SOCEvent, TelemetryPayload
from common.kafka import create_producer, publish_event
from ml.features.network_flow import NETWORK_FLOW_FEATURES


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

# Ranges follow the shared feature order and exist only to generate synthetic
# source telemetry. The attack label remains isolated in ground_truth.
TELEMETRY_RANGES = {
    "failed_login": (
        (50_000, 500_000), (4, 15), (2, 12), (1_000, 50_000),
        (10, 200), (40, 400), (40, 400), (1, 8), (1, 15), (40, 400),
    ),
    "port_scan": (
        (100, 20_000), (50, 500), (0, 20), (100_000, 5_000_000),
        (5_000, 50_000), (40, 120), (0, 100), (20, 300), (0, 10), (40, 120),
    ),
    "malware_detected": (
        (500_000, 10_000_000), (50, 1_000), (50, 1_000),
        (1_000_000, 30_000_000), (500, 15_000), (200, 1_400),
        (200, 1_400), (1, 50), (20, 500), (200, 1_400),
    ),
    "ddos_attempt": (
        (1_000, 500_000), (1_000, 100_000), (0, 1_000),
        (50_000_000, 500_000_000), (100_000, 500_000), (40, 800),
        (0, 500), (100, 50_000), (0, 500), (40, 800),
    ),
    "unauthorized_access": (
        (100_000, 5_000_000), (20, 500), (20, 500),
        (500_000, 15_000_000), (200, 10_000), (100, 1_000),
        (100, 1_000), (1, 30), (10, 300), (100, 1_000),
    ),
    "privilege_escalation": (
        (100_000, 8_000_000), (20, 700), (20, 700),
        (750_000, 20_000_000), (300, 12_000), (100, 1_200),
        (100, 1_200), (1, 40), (10, 400), (100, 1_200),
    ),
}


def generate_telemetry(attack_type: str, rng: random.Random) -> TelemetryPayload:
    ranges = TELEMETRY_RANGES[attack_type]
    if len(ranges) != len(NETWORK_FLOW_FEATURES):
        raise ValueError("Simulator telemetry profile does not match feature contract")
    flow_features = {
        feature: round(rng.uniform(lower, upper), 4)
        for feature, (lower, upper) in zip(NETWORK_FLOW_FEATURES, ranges)
    }
    return TelemetryPayload(flow_features=flow_features)


def create_attack(
    attack_type: str | None = None,
    rng: random.Random | None = None,
) -> SOCEvent:
    generator = rng or random.Random()
    attack_type = attack_type or generator.choice(ATTACK_TYPES)
    return SOCEvent.create_ingested(
        event="network_flow_observed",
        source_ip=generator.choice(IPS),
        user=generator.choice(USERS),
        telemetry=generate_telemetry(attack_type, generator),
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
