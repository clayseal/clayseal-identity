"""Thin HTTP transport around the Clay Seal REST API.

Responsibilities:
- attach the tenant ``X-API-Key`` and base URL,
- translate the backend's ``{error:{code,message,suggestion}}`` envelope into
  typed :class:`~clayseal.errors.ClaySealError` subclasses,
- retry transient network/5xx failures with bounded exponential backoff,
- stay injectable: tests pass an ``httpx`` transport that targets the FastAPI
  app in-process (``httpx.ASGITransport``) so the whole SDK is exercised with no
  network and no running server.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from .errors import TransportError, from_envelope

_logger = logging.getLogger("clayseal.http")

# Methods with no server-side side effects, so they are safe to retry even after
# a response (or partial response) was received.
_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class HttpClient:
    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        *,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
        headers: dict[str, str] | None = None,
        max_retries: int = 2,
        backoff_base: float = 0.2,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        # Bounded exponential backoff for transient failures. Set max_retries=0
        # to disable retries entirely.
        self._max_retries = max(0, max_retries)
        self._backoff_base = backoff_base
        default_headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            default_headers["X-API-Key"] = api_key
        if headers:
            default_headers.update(headers)
        # ``transport`` lets tests bind to the ASGI app; in production httpx
        # opens real connections to ``base_url``.
        self._client = httpx.Client(
            base_url=self.base_url,
            headers=default_headers,
            timeout=timeout,
            transport=transport,
        )

    # --- lifecycle --------------------------------------------------------- #
    def close(self) -> None:
        self._client.close()

    # --- core request ------------------------------------------------------ #
    def request(
        self,
        method: str,
        path: str,
        *,
        json: dict | None = None,
        params: dict | None = None,
    ) -> Any:
        idempotent = method.upper() in _IDEMPOTENT_METHODS
        attempt = 0
        while True:
            try:
                resp = self._client.request(method, path, json=json, params=params)
            except httpx.HTTPError as exc:  # network/timeout/connect
                # Connect-class errors mean the request never reached the server,
                # so they are safe to retry for any method. Other transport errors
                # (e.g. a read timeout after the request was sent) are retried
                # only for idempotent methods.
                connect_error = isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout))
                if attempt < self._max_retries and (connect_error or idempotent):
                    self._backoff(attempt, path, type(exc).__name__)
                    attempt += 1
                    continue
                raise TransportError(
                    f"Could not reach Clay Seal at {self.base_url}: {exc}",
                    suggestion="Check CLAYSEAL_BASE_URL and that the service is reachable.",
                ) from exc

            # Retry transient server errors (5xx) for idempotent methods only.
            if resp.status_code >= 500 and idempotent and attempt < self._max_retries:
                self._backoff(attempt, path, f"HTTP {resp.status_code}")
                attempt += 1
                continue

            return self._parse(resp, path)

    def _backoff(self, attempt: int, path: str, reason: str) -> None:
        delay = self._backoff_base * (2 ** attempt)
        _logger.warning(
            "Retrying %s after %s (attempt %d/%d, backoff %.2fs)",
            path, reason, attempt + 1, self._max_retries, delay,
        )
        time.sleep(delay)

    @staticmethod
    def _parse(resp: httpx.Response, path: str) -> Any:
        if resp.status_code >= 400:
            payload: dict = {}
            try:
                payload = resp.json()
            except ValueError:
                payload = {}
            if isinstance(payload, dict) and "error" in payload:
                raise from_envelope(payload, resp.status_code)
            raise TransportError(
                f"Request to {path} failed with HTTP {resp.status_code}.",
                suggestion="Inspect the response body; this was not a structured Clay Seal error.",
                status_code=resp.status_code,
            )

        if resp.status_code == 204 or not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return resp.text

    # --- verbs ------------------------------------------------------------- #
    def get(self, path: str, *, params: dict | None = None) -> Any:
        return self.request("GET", path, params=params)

    def post(self, path: str, *, json: dict | None = None, params: dict | None = None) -> Any:
        return self.request("POST", path, json=json, params=params)
