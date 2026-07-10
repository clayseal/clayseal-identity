"""MCP-oriented identity helpers (client side).

These helpers give MCP clients a conventional way to carry Clay Seal agent
identity on HTTP transports. The server-side counterpart — verifying the
credential and authorizing each tool call — lives in
:mod:`clayseal.identity.integrations.mcp_server`.

Three headers travel together:

- ``Authorization: Bearer <jwt>`` — who the agent is. Verified at the
  transport; requests without a valid credential get a 401.
- ``X-ClaySeal-Biscuit`` — what the agent may do. The server authorizes each
  tool call against this (possibly attenuated) capability token.
- ``X-ClaySeal-PoP`` — proof the caller holds the workload key the tokens are
  bound to. Clay Seal capability tokens are sender-constrained, so a stolen
  biscuit without the key authorizes nothing. The proof is signed over the
  MCP endpoint URL, HTTP method, and the biscuit's hash, and carries a
  freshness timestamp — rebuild headers (they are cheap) at least every few
  minutes and whenever the endpoint changes.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

BISCUIT_HEADER = "X-ClaySeal-Biscuit"
POP_HEADER = "X-ClaySeal-PoP"


def _token(session_or_token: Any) -> str:
    if isinstance(session_or_token, str):
        return session_or_token
    return str(session_or_token.token)


def _biscuit(session_or_token: Any) -> str | None:
    credential = getattr(session_or_token, "credential", None)
    return getattr(credential, "biscuit", None)


def authorization_header(session_or_token: Any) -> dict[str, str]:
    """Return an Authorization header for MCP HTTP transports."""
    return {"Authorization": f"Bearer {_token(session_or_token)}"}


def pop_header(session: Any, *, server_url: str, method: str = "POST") -> dict[str, str]:
    """Sign a connection-level proof-of-possession for an MCP endpoint.

    Requires a session that holds its workload private key and a Biscuit
    (one returned by ``identify``/``attenuate``). Returns ``{}`` when either
    is missing.
    """
    from cryptography.hazmat.primitives import serialization

    from clayseal.workload_keys import keyhash_for_pem, sign_request_pop, token_hash

    biscuit = _biscuit(session)
    privkey_pem = getattr(session, "_workload_private_pem", None)
    if not biscuit or not privkey_pem:
        return {}
    private_key = serialization.load_pem_private_key(privkey_pem.encode(), password=None)
    pubkey_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    proof = {
        "challenge": uuid.uuid4().hex,
        "htm": method,
        "htu": server_url,
        "ath": token_hash(str(biscuit)),
        "iat": int(time.time()),
        "jti": uuid.uuid4().hex,
        "pubkey_pem": pubkey_pem,
    }
    proof["signature_b64"] = sign_request_pop(
        privkey_pem,
        keyhash_for_pem(pubkey_pem),
        proof["challenge"],
        htm=proof["htm"],
        htu=proof["htu"],
        ath=proof["ath"],
        iat=proof["iat"],
        jti=proof["jti"],
        operation=None,
    )
    return {POP_HEADER: json.dumps(proof, separators=(",", ":"))}


def tool_headers(
    session_or_token: Any,
    extra: dict[str, str] | None = None,
    *,
    server_url: str | None = None,
) -> dict[str, str]:
    """Merge Clay Seal identity headers with caller-supplied headers.

    Pass ``server_url`` (the MCP endpoint the client POSTs to) to include the
    proof-of-possession header — Clay Seal-protected servers require it, since
    capability tokens are bound to the agent's workload key.
    """
    headers = dict(extra or {})
    headers.update(authorization_header(session_or_token))
    biscuit = _biscuit(session_or_token)
    if biscuit:
        headers[BISCUIT_HEADER] = str(biscuit)
    if server_url is not None:
        headers.update(pop_header(session_or_token, server_url=server_url))
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
