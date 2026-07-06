"""CIMD: Client ID Metadata Documents for MCP client identification."""

from __future__ import annotations

import json

import pytest

from agentauth.backend.cimd import (
    MAX_DOCUMENT_BYTES,
    ClientMetadataError,
    fetch_client_metadata,
    validate_client_id_url,
)

CLIENT_ID = "https://client.example/oauth-client"


class _Response:
    def __init__(self, content: bytes):
        self.content = content

    def raise_for_status(self):
        pass


def _http_get_returning(document: dict):
    def http_get(url: str) -> _Response:
        assert url == CLIENT_ID
        return _Response(json.dumps(document).encode())

    return http_get


def test_valid_document_roundtrips():
    document = {
        "client_id": CLIENT_ID,
        "client_name": "Example MCP client",
        "redirect_uris": ["https://client.example/callback", "http://127.0.0.1/cb"],
        "token_endpoint_auth_method": "private_key_jwt",
    }
    assert fetch_client_metadata(CLIENT_ID, http_get=_http_get_returning(document)) == document


@pytest.mark.parametrize(
    "client_id, match",
    [
        ("http://client.example/c", "https"),
        ("https://user:pw@client.example/c", "credentials"),
        ("https://client.example/c#frag", "fragment"),
        ("https://localhost/c", "not allowed"),
        ("https://127.0.0.1/c", "globally routable"),
        ("https://10.0.0.8/c", "globally routable"),
        ("https://[::1]/c", "globally routable"),
    ],
)
def test_bad_client_id_urls_rejected(client_id, match):
    with pytest.raises(ClientMetadataError, match=match):
        validate_client_id_url(client_id)


def test_client_id_mismatch_rejected():
    document = {"client_id": "https://evil.example/other"}
    with pytest.raises(ClientMetadataError, match="must equal the URL"):
        fetch_client_metadata(CLIENT_ID, http_get=_http_get_returning(document))


def test_oversized_document_rejected():
    def http_get(url: str) -> _Response:
        return _Response(b"x" * (MAX_DOCUMENT_BYTES + 1))

    with pytest.raises(ClientMetadataError, match="exceeds"):
        fetch_client_metadata(CLIENT_ID, http_get=http_get)


def test_non_json_and_non_object_rejected():
    with pytest.raises(ClientMetadataError, match="not valid JSON"):
        fetch_client_metadata(CLIENT_ID, http_get=lambda url: _Response(b"<html>"))
    with pytest.raises(ClientMetadataError, match="JSON object"):
        fetch_client_metadata(CLIENT_ID, http_get=lambda url: _Response(b'["a"]'))


def test_insecure_redirect_uri_rejected():
    document = {
        "client_id": CLIENT_ID,
        "redirect_uris": ["http://client.example/callback"],
    }
    with pytest.raises(ClientMetadataError, match="redirect_uri"):
        fetch_client_metadata(CLIENT_ID, http_get=_http_get_returning(document))
