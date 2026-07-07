"""OAuth Client ID Metadata Documents (CIMD) — MCP client identification.

The MCP authorization spec deprecated Dynamic Client Registration in favor of
CIMD: a client identifies itself with an HTTPS URL as ``client_id``, and the
authorization server fetches that URL to obtain the client's metadata
(name, redirect URIs, auth method). This module is the fetch/validate side an
AS needs:

    metadata = fetch_client_metadata("https://client.example/oauth-client")

Validation follows the draft's trust rules — the URL must be HTTPS with a
host and path, no credentials or fragment, and the fetched document's
``client_id`` MUST equal the URL it was fetched from (proof the host vouches
for that identity). Documents are size-capped and returned as plain dicts;
callers decide caching and which grants the client may use.

SSRF posture: literal loopback/private/link-local hosts are rejected before
fetching. DNS names that *resolve* to private ranges are the deployment's
egress policy to enforce (a resolver-level guard here would still lose to
DNS rebinding); front the backend with an egress proxy when it runs inside a
trust boundary.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any, Callable
from urllib.parse import urlsplit

MAX_DOCUMENT_BYTES = 64 * 1024
FETCH_TIMEOUT_SECONDS = 5.0

_BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


class ClientMetadataError(ValueError):
    """A client_id URL or its metadata document failed validation."""


def validate_client_id_url(client_id: str) -> None:
    """Enforce the CIMD client_id URL shape; raise ``ClientMetadataError``."""
    parts = urlsplit(client_id)
    if parts.scheme != "https":
        raise ClientMetadataError("client_id must be an https URL")
    if not parts.hostname:
        raise ClientMetadataError("client_id must include a host")
    if parts.username or parts.password:
        raise ClientMetadataError("client_id must not carry credentials")
    if parts.fragment:
        raise ClientMetadataError("client_id must not carry a fragment")
    host = parts.hostname.lower().rstrip(".")
    if host in _BLOCKED_HOSTNAMES:
        raise ClientMetadataError(f"client_id host {host!r} is not allowed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return  # a DNS name; egress policy owns resolution-time guarantees
    if not address.is_global:
        raise ClientMetadataError(
            f"client_id host {host!r} is not a globally routable address"
        )


def fetch_client_metadata(
    client_id: str,
    *,
    http_get: Callable[[str], Any] | None = None,
    timeout: float = FETCH_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Fetch and validate a client's metadata document from its ``client_id`` URL.

    ``http_get`` is injectable for tests and custom transports; it must return
    an object with ``content`` (bytes) and ``raise_for_status()``. Returns the
    validated metadata dict.
    """
    validate_client_id_url(client_id)
    if http_get is None:
        from agentauth.core.safe_http import safe_http_get

        def http_get(url: str) -> Any:
            class _Response:
                def __init__(self, content: bytes) -> None:
                    self.content = content

                def raise_for_status(self) -> None:
                    return None

            return _Response(
                safe_http_get(
                    url,
                    timeout=timeout,
                    headers={"Accept": "application/json"},
                )
            )

    response = http_get(client_id)
    response.raise_for_status()
    body = response.content
    if len(body) > MAX_DOCUMENT_BYTES:
        raise ClientMetadataError(
            f"client metadata document exceeds {MAX_DOCUMENT_BYTES} bytes"
        )
    try:
        document = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ClientMetadataError("client metadata document is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ClientMetadataError("client metadata document must be a JSON object")
    if document.get("client_id") != client_id:
        raise ClientMetadataError(
            "client metadata client_id must equal the URL it was fetched from"
        )
    redirect_uris = document.get("redirect_uris")
    if redirect_uris is not None:
        if not isinstance(redirect_uris, list) or not all(
            isinstance(uri, str) for uri in redirect_uris
        ):
            raise ClientMetadataError("redirect_uris must be a list of strings")
        for uri in redirect_uris:
            scheme = urlsplit(uri).scheme
            if scheme not in ("https", "http") or (
                scheme == "http" and urlsplit(uri).hostname not in ("127.0.0.1", "::1")
            ):
                raise ClientMetadataError(
                    f"redirect_uri {uri!r} must be https (or http on loopback)"
                )
    return document
