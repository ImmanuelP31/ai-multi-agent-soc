"""Replay-safe local observer for canonical ingestion events."""

from pathlib import Path
import sys

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from common.events import deserialize_event
from common.kafka import consume_forever, create_consumer


def main() -> None:
    consumer = create_consumer("soc_logs", "soc-log-observer")
    print("Listening for SOC logs...")

    def handle(payload: dict) -> None:
        event = deserialize_event(payload)
        print(f"Received: {event.to_message()}", flush=True)

    consume_forever(consumer, handle, "soc-log-observer")


if __name__ == "__main__":
    main()
