"""Kafka configuration shared by the SOC agents."""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Callable
from typing import Any

from common.events import SOCEvent

SOC_TOPICS = (
    "soc_logs",
    "soc_alerts",
    "investigated_alerts",
    "threat_enriched_alerts",
    "remediation_actions",
)


def bootstrap_servers() -> str:
    return os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")


def create_consumer(topic: str, group_id: str, *, offset_reset: str = "earliest"):
    from kafka import KafkaConsumer

    return KafkaConsumer(
        topic,
        bootstrap_servers=bootstrap_servers(),
        group_id=group_id,
        enable_auto_commit=False,
        auto_offset_reset=offset_reset,
    )


def create_producer():
    from kafka import KafkaProducer

    return KafkaProducer(
        bootstrap_servers=bootstrap_servers(),
        acks="all",
        retries=5,
        value_serializer=lambda value: json.dumps(value, default=str).encode("utf-8"),
    )


def check_kafka(timeout_seconds: float = 3.0) -> list[str]:
    """Verify broker reachability and return the currently visible topics."""

    from kafka import KafkaAdminClient

    timeout_ms = max(1, int(timeout_seconds * 1000))
    client = KafkaAdminClient(
        bootstrap_servers=bootstrap_servers(),
        request_timeout_ms=timeout_ms,
        api_version_auto_timeout_ms=timeout_ms,
        client_id="soc-readiness",
    )
    try:
        return sorted(client.list_topics())
    finally:
        client.close()


def publish_event(producer, topic: str, event: SOCEvent) -> None:
    producer.send(topic, key=event.kafka_key(), value=event.to_message()).get(timeout=15)


def commit_message(consumer, message) -> None:
    from kafka.structs import OffsetAndMetadata, TopicPartition

    partition = TopicPartition(message.topic, message.partition)
    offset = OffsetAndMetadata(message.offset + 1, "", -1)
    consumer.commit({partition: offset})


def retry_message(
    consumer,
    message,
    agent_name: str,
    exc: Exception,
    *,
    retry_delay: float = 1.0,
) -> None:
    from kafka.structs import TopicPartition

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
    if retry_delay > 0:
        time.sleep(retry_delay)


def decode_message_value(value: Any) -> dict[str, Any]:
    """Decode one Kafka value so malformed payloads stay uncommitted."""

    if isinstance(value, dict):
        return value
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Kafka message is not valid UTF-8") from exc
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("Kafka message is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("Kafka message must contain a JSON object")
    return value


def process_message(
    consumer,
    message,
    handler: Callable[[dict[str, Any]], None],
    agent_name: str,
    *,
    retry_delay: float = 1.0,
    commit_fn: Callable[[Any, Any], None] | None = None,
    retry_fn: Callable[..., None] | None = None,
) -> bool:
    """Process and acknowledge one message, returning whether it committed."""

    try:
        handler(decode_message_value(message.value))
        (commit_fn or commit_message)(consumer, message)
        return True
    except Exception as exc:
        (retry_fn or retry_message)(
            consumer,
            message,
            agent_name,
            exc,
            retry_delay=retry_delay,
        )
        return False


def consume_forever(
    consumer,
    handler: Callable[[dict[str, Any]], None],
    agent_name: str,
) -> None:
    for message in consumer:
        process_message(consumer, message, handler, agent_name)
