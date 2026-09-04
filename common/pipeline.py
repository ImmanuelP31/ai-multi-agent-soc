"""Finite, testable execution boundary shared by Kafka stage adapters."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from common.events import SOCEvent, deserialize_event


class EventProcessor(Protocol):
    def process(self, event: SOCEvent) -> SOCEvent: ...


def run_stage(
    payload: dict,
    processor: EventProcessor,
    persist: Callable[[SOCEvent], object],
    *,
    after_persist: Callable[[SOCEvent], None] | None = None,
    publish: Callable[[SOCEvent], None] | None = None,
) -> SOCEvent:
    """Validate, enrich, persist, perform local output, then publish."""

    event = processor.process(deserialize_event(payload))
    persist(event)
    if after_persist is not None:
        after_persist(event)
    if publish is not None:
        publish(event)
    return event
