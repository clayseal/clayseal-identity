"""Observability (High 6): /ready readiness probe, /health liveness, per-request
id header, and structured JSON log formatting."""
from __future__ import annotations

import json
import logging

from agentauth.backend.observability import JsonFormatter, configure_logging


def test_health_is_liveness(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_ready_runs_db_check(client):
    resp = client.get("/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["checks"]["database"] == "ok"


def test_request_id_header_present(client):
    resp = client.get("/health")
    header_names = {k.lower() for k in resp.headers}
    assert "x-request-id" in header_names


def test_supplied_request_id_is_echoed(client):
    resp = client.get("/health", headers={"X-Request-ID": "abc123"})
    assert resp.headers["x-request-id"] == "abc123"


def test_json_formatter_emits_structured_fields():
    record = logging.LogRecord(
        name="agentauth.access",
        level=logging.INFO,
        pathname="f.py",
        lineno=1,
        msg="request",
        args=(),
        exc_info=None,
    )
    record.event = "request"
    record.status = 200
    record.method = "GET"
    record.path = "/health"

    parsed = json.loads(JsonFormatter().format(record))
    assert parsed["message"] == "request"
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "agentauth.access"
    assert parsed["status"] == 200
    assert parsed["method"] == "GET"
    assert parsed["path"] == "/health"


def test_configure_logging_installs_json_handler():
    configure_logging()
    logger = logging.getLogger("agentauth.access")
    assert logger.handlers
    assert isinstance(logger.handlers[0].formatter, JsonFormatter)
