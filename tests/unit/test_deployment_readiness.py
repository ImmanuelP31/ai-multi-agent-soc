from __future__ import annotations

from types import SimpleNamespace

from fastapi import Response
import pytest

from agents.investigation_agent import validate_sequence_runtime
from backend import main as backend_main
from common.health import ServiceHealth
from common.kafka import SOC_TOPICS


def test_service_health_distinguishes_liveness_from_readiness():
    health = ServiceHealth("test-agent")

    starting = health.snapshot()
    assert starting["live"] is True
    assert starting["ready"] is False

    health.set_ready(model_status="loaded")
    ready = health.snapshot()
    assert ready["ready"] is True
    assert ready["model_status"] == "loaded"


def test_required_sequence_mode_rejects_unavailable_model():
    predictor = SimpleNamespace(
        available=False,
        model_status="missing_model_artifacts",
        unavailable_detail="preprocessor missing",
    )

    with pytest.raises(RuntimeError, match="sequence prediction is required"):
        validate_sequence_runtime(predictor, "required")


def test_optional_sequence_mode_keeps_unavailable_status_explicit():
    predictor = SimpleNamespace(
        available=False,
        model_status="requires_retraining",
        unavailable_detail="training required",
    )

    validate_sequence_runtime(predictor, "optional")


def test_invalid_sequence_mode_is_rejected():
    predictor = SimpleNamespace(available=True)

    with pytest.raises(ValueError, match="SEQUENCE_PREDICTION_MODE"):
        validate_sequence_runtime(predictor, "automatic")


def test_cors_origins_are_configurable_and_wildcards_are_rejected(monkeypatch):
    monkeypatch.setenv(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:5173, https://soc.example.test ",
    )
    assert backend_main.configured_cors_origins() == [
        "http://localhost:5173",
        "https://soc.example.test",
    ]

    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "*")
    with pytest.raises(ValueError, match="Wildcard CORS"):
        backend_main.configured_cors_origins()


def test_backend_readiness_checks_database_redis_and_required_topics(monkeypatch):
    monkeypatch.setattr(backend_main, "init_db", lambda: None)
    monkeypatch.setattr(backend_main, "get_redis", lambda: object())
    monkeypatch.setattr(backend_main, "check_kafka", lambda: list(SOC_TOPICS))
    monkeypatch.setattr(backend_main, "PIPELINE_HEALTH_URLS", "")
    response = Response()

    payload = backend_main.health(response)

    assert payload["status"] == "ready"
    assert response.status_code == 200
    assert payload["checks"]["kafka"]["missing_topics"] == []


def test_backend_readiness_fails_when_a_pipeline_topic_is_missing(monkeypatch):
    monkeypatch.setattr(backend_main, "init_db", lambda: None)
    monkeypatch.setattr(backend_main, "get_redis", lambda: object())
    monkeypatch.setattr(backend_main, "check_kafka", lambda: ["soc_logs"])
    monkeypatch.setattr(backend_main, "PIPELINE_HEALTH_URLS", "")
    response = Response()

    payload = backend_main.health(response)

    assert payload["status"] == "not_ready"
    assert response.status_code == 503
    assert "soc_alerts" in payload["checks"]["kafka"]["missing_topics"]
