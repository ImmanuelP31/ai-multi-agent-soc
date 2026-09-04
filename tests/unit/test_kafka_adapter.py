from __future__ import annotations

from dataclasses import dataclass

import pytest

from common.kafka import decode_message_value, process_message


@dataclass
class FakeMessage:
    value: object
    topic: str = "soc_logs"
    partition: int = 0
    offset: int = 17


class FakeConsumer:
    def __init__(self):
        self.commits = []
        self.seeks = []

    def commit(self, offsets):
        self.commits.append(offsets)

    def seek(self, partition, offset):
        self.seeks.append((partition, offset))


def record_commit(consumer, message):
    consumer.commits.append((message.topic, message.partition, message.offset + 1))


def record_retry(consumer, message, agent_name, exc, *, retry_delay):
    consumer.seeks.append(((message.topic, message.partition), message.offset))


def test_successful_message_is_committed_after_handler():
    consumer = FakeConsumer()
    calls = []
    message = FakeMessage(b'{"event_id":"test"}')

    committed = process_message(
        consumer,
        message,
        lambda payload: calls.append(payload),
        "test-agent",
        retry_delay=0,
        commit_fn=record_commit,
        retry_fn=record_retry,
    )

    assert committed is True
    assert calls == [{"event_id": "test"}]
    assert len(consumer.commits) == 1
    assert consumer.seeks == []


@pytest.mark.parametrize(
    "failure",
    [
        RuntimeError("database unavailable"),
        RuntimeError("downstream Kafka publish failed"),
        RuntimeError("Redis sequence state unavailable"),
    ],
)
def test_processing_failure_is_not_committed_and_is_rewound(failure):
    consumer = FakeConsumer()
    message = FakeMessage({"event_id": "test"})

    def failing_handler(payload):
        raise failure

    committed = process_message(
        consumer,
        message,
        failing_handler,
        "test-agent",
        retry_delay=0,
        commit_fn=record_commit,
        retry_fn=record_retry,
    )

    assert committed is False
    assert consumer.commits == []
    assert len(consumer.seeks) == 1
    assert consumer.seeks[0][1] == message.offset


@pytest.mark.parametrize(
    "payload",
    [b"not-json", b"[]", b"\xff", "42"],
)
def test_malformed_kafka_message_is_rejected_without_commit(payload):
    consumer = FakeConsumer()
    handler_calls = []

    committed = process_message(
        consumer,
        FakeMessage(payload),
        lambda value: handler_calls.append(value),
        "test-agent",
        retry_delay=0,
        commit_fn=record_commit,
        retry_fn=record_retry,
    )

    assert committed is False
    assert handler_calls == []
    assert consumer.commits == []
    assert len(consumer.seeks) == 1


def test_decoder_accepts_existing_dict_for_unit_adapters():
    payload = {"event_id": "already-decoded"}

    assert decode_message_value(payload) is payload
