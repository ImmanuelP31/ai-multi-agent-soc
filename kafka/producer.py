"""Simple canonical SOC event producer for local Kafka testing."""

from pathlib import Path
import sys
import time

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from common.events import GroundTruthMetadata, SOCEvent
from common.kafka import create_producer, publish_event


LOGS = [
    ("failed_login", "192.168.1.10"),
    ("port_scan", "192.168.1.20"),
    ("malware_detected", "192.168.1.30"),
]


def main() -> None:
    producer = create_producer()
    while True:
        for event_name, source_ip in LOGS:
            event = SOCEvent.create_ingested(
                event=event_name,
                source_ip=source_ip,
                user=None,
                ground_truth=GroundTruthMetadata(
                    synthetic=True,
                    attack_label=event_name,
                    generator="kafka/producer.py",
                ),
            )
            publish_event(producer, "soc_logs", event)
            print(f"Sent: {event.to_message()}", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
