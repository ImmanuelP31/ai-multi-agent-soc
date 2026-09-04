"""Kafka configuration shared by the SOC agents."""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Callable
from typing import Any

from kafka import KafkaConsumer, KafkaProducer
from kafka.structs import OffsetAndMetadata, TopicPartition

from common.events import SOCEvent


def bootstrap_servers() -> str:
    return os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")


def create_consumer(topic: str, group_id: str, *, offset_reset: str = "earliest"):
    return KafkaConsumer(
        topic,
        bootstrap_servers=bootstrap_servers(),
        group_id=group_id,
        enable_auto_commit=False,
        auto_offset_reset=offset_reset,
        value_deserializer=lambda value: json.loads(value.decode("utf-8")),
    )


def create_producer():
    return KafkaProducer(
        bootstrap_servers=bootstrap_servers(),
        acks="all",
        retries=5,
        value_serializer=lambda value: json.dumps(value, default=str).encode("utf-8"),
    )


def publish_event(producer, topic: str, event: SOCEvent) -> None:
    producer.send(topic, key=event.kafka_key(), value=event.to_message()).get(timeout=15)


def commit_message(consumer, message) -> None:
    partition = TopicPartition(message.topic, message.partition)
    offset = OffsetAndMetadata(message.offset + 1, "", -1)
    consumer.commit({partition: offset})


def retry_message(consumer, message, agent_name: str, exc: Exception) -> None:
    partition = TopicPartition(message.topic, message.partition)
    event_id = None
    if isinstance(message.value, dict):
        event_id = message.value.get("event_id")
    print(
        json.dumps(
            {
                "processing_error": str(exc),
                "agent": agent_name,
                "topic": message.topic,
                "partition": message.partition,
                "offset": message.offset,
                "event_id": event_id,
                "action": "offset_not_committed; retrying",
            }
        ),
        file=sys.stderr,
        flush=True,
    )
    consumer.seek(partition, message.offset)
    time.sleep(1)


def consume_forever(
    consumer,
    handler: Callable[[dict[str, Any]], None],
    agent_name: str,
) -> None:
    for message in consumer:
        try:
            handler(message.value)
            commit_message(consumer, message)
        except Exception as exc:
            retry_message(consumer, message, agent_name, exc)
