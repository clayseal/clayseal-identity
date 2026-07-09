"""MCP-oriented identity helpers.

These helpers do not implement MCP authorization. They give MCP clients and
servers a tiny, conventional way to carry and log Clay Seal agent identity.
"""
from __future__ import annotations

from typing import Any


def _token(session_or_token: Any) -> str:
    if isinstance(session_or_token, str):
        return session_or_token
    return str(getattr(session_or_token, "token"))


def authorization_header(session_or_token: Any) -> dict[str, str]:
    """Return an Authorization header for MCP HTTP transports."""
    return {"Authorization": f"Bearer {_token(session_or_token)}"}


def tool_headers(session_or_token: Any, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Merge Clay Seal identity headers with caller-supplied headers."""
    headers = dict(extra or {})
    headers.update(authorization_header(session_or_token))
    return headers


def identity_metadata(session_or_token: Any) -> dict[str, Any]:
    """Small metadata dict for MCP logs/tool-call context."""
    credential = getattr(session_or_token, "credential", None)
    return {
        "clayseal.identity": True,
        "agent_id": getattr(session_or_token, "agent_id", ""),
        "agent_type": getattr(session_or_token, "agent_type", ""),
        "owner": getattr(session_or_token, "owner", ""),
        "spiffe_id": getattr(credential, "spiffe_id", ""),
    }
