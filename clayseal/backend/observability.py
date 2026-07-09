"""Structured (JSON) logging + request/auth-failure logging middleware.

Everything is emitted as one JSON object per line so a log shipper
(CloudWatch/Fluent Bit) can index fields without regex. We log request
metadata only -- method, path, status, latency, client IP, a request id, and
(on auth failures) the error code. We NEVER log the request/response body,
headers, the ``X-API-Key`` / ``X-Admin-Key`` values, tokens, or any PII.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .config import Settings, get_settings

LOGGER_NAME = "clayseal"
_ACCESS_LOGGER = "clayseal.access"

# Fields we set explicitly on the LogRecord; everything else the record carries
# by default is dropped so we don't accidentally leak args/exc text with secrets.
_STANDARD_KEYS = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "taskName",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Merge structured extras (event=..., status=..., etc.).
        for key, value in record.__dict__.items():
            if key not in _STANDARD_KEYS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc_type"] = getattr(record.exc_info[0], "__name__", str(record.exc_info[0]))
        return json.dumps(payload, default=str)


def configure_logging(settings: Settings | None = None) -> None:
    """Install the JSON formatter on the ClaySeal loggers (idempotent)."""
    settings = settings or get_settings()
    level = getattr(logging, settings.log_level, logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    for name in (LOGGER_NAME, _ACCESS_LOGGER):
        logger = logging.getLogger(name)
        logger.handlers = [handler]
        logger.setLevel(level)
        logger.propagate = False


def get_logger(name: str = LOGGER_NAME) -> logging.Logger:
    return logging.getLogger(name)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Emit one structured access-log line per request; flag auth failures."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        logger = logging.getLogger(_ACCESS_LOGGER)
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        start = time.perf_counter()
        client_ip = request.client.host if request.client else None
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            logger.exception(
                "request failed",
                extra={
                    "event": "request",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "client_ip": client_ip,
                    "duration_ms": duration_ms,
                    "status": 500,
                },
            )
            raise

        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        response.headers["X-Request-ID"] = request_id
        extra = {
            "event": "request",
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "client_ip": client_ip,
            "duration_ms": duration_ms,
            "status": response.status_code,
        }
        if response.status_code in (401, 403):
            # Auth/authorization failure -- surface it, but only the status/code,
            # never the presented credential.
            logger.warning("auth failure", extra=extra)
        elif response.status_code >= 500:
            logger.error("request error", extra=extra)
        else:
            logger.info("request", extra=extra)
        return response
