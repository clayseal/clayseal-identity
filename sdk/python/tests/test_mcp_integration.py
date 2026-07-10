"""MCP server integration: transport-level token verification and per-tool
capability authorization (Biscuit + proof-of-possession), exercised with real
credentials from the in-process backend.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import pytest

from clayseal.identity.errors import CapabilityDeniedError
from clayseal.identity.integrations.mcp import (
    BISCUIT_HEADER,
    POP_HEADER,
    pop_header,
    tool_headers,
)
from clayseal.identity.integrations.mcp_server import (
    ClaySealTokenVerifier,
    InMemoryReplayCache,
    ToolGuard,
    default_tool_capability,
)

SERVER_URL = "https://tools.example.com/mcp"
TOOL_CAPS = [
    {"resource": "tool", "action": "search_web"},
    {"resource": "tool", "action": "read_docs"},
]


@pytest.fixture
def session(auth):
    return auth.identify(
        agent_type="assistant", owner="a@b.c", capabilities=TOOL_CAPS
    )


@pytest.fixture
def verifier(session, base_url):
    claims = session.validate().claims or {}
    jwks = httpx.get(f"{base_url}/t/{claims['customer_id']}/jwks.json").json()
    return ClaySealTokenVerifier(jwks=jwks, issuer=claims["iss"])


@pytest.fixture
def guard(session):
    return ToolGuard(
        biscuit_root_public_key=session.credential.biscuit_root_public_key,
        server_url=SERVER_URL,
    )


def _pop(session, url=SERVER_URL) -> str:
    return pop_header(session, server_url=url)[POP_HEADER]


# --- client helpers ---------------------------------------------------------- #
def test_tool_headers_carry_bearer_biscuit_and_pop(session):
    headers = tool_headers(session, server_url=SERVER_URL)
    assert headers["Authorization"] == f"Bearer {session.token}"
    assert headers[BISCUIT_HEADER] == session.credential.biscuit
    assert POP_HEADER in headers


def test_tool_headers_for_plain_string_have_no_capability_headers():
    headers = tool_headers("just-a-jwt-string", server_url=SERVER_URL)
    assert BISCUIT_HEADER not in headers
    assert POP_HEADER not in headers


# --- transport verification --------------------------------------------------- #
def test_verify_token_accepts_valid_credential(verifier, session):
    access = asyncio.run(verifier.verify_token(session.token))
    assert access is not None
    assert access.client_id == session.agent_id
    assert access.claims["cnf"]["jkt"]


def test_verify_token_rejects_tampered_token(verifier, session):
    head, sig = session.token.rsplit(".", 1)
    flipped = ("B" if sig[0] == "A" else "A") + sig[1:]
    assert asyncio.run(verifier.verify_token(f"{head}.{flipped}")) is None


def test_verify_token_rejects_wrong_issuer(session, base_url):
    claims = session.validate().claims or {}
    jwks = httpx.get(f"{base_url}/t/{claims['customer_id']}/jwks.json").json()
    verifier = ClaySealTokenVerifier(jwks=jwks, issuer="attacker.example")
    assert asyncio.run(verifier.verify_token(session.token)) is None


def test_verify_token_callable_jwks(session, base_url):
    claims = session.validate().claims or {}

    def fetch():
        return httpx.get(f"{base_url}/t/{claims['customer_id']}/jwks.json").json()

    verifier = ClaySealTokenVerifier(jwks=fetch, issuer=claims["iss"])
    assert asyncio.run(verifier.verify_token(session.token)) is not None


# --- per-tool authorization ---------------------------------------------------- #
def test_granted_tools_allowed_others_denied(guard, session):
    biscuit = session.credential.biscuit
    pop = _pop(session)
    assert guard.authorize_call("search_web", biscuit_b64=biscuit, pop_json=pop) == (
        True,
        "authorized",
    )
    assert guard.authorize_call("read_docs", biscuit_b64=biscuit, pop_json=pop)[0] is True
    allowed, _ = guard.authorize_call("delete_records", biscuit_b64=biscuit, pop_json=pop)
    assert allowed is False


def test_no_biscuit_fails_closed(guard, session):
    allowed, reason = guard.authorize_call(
        "search_web", biscuit_b64=None, pop_json=_pop(session)
    )
    assert allowed is False
    assert BISCUIT_HEADER in reason


def test_no_pop_fails_closed(guard, session):
    """Sender-constraint: the Biscuit alone (e.g. exfiltrated from a log)
    authorizes nothing without a proof signed by the bound workload key."""
    allowed, reason = guard.authorize_call(
        "search_web", biscuit_b64=session.credential.biscuit, pop_json=None
    )
    assert allowed is False
    assert POP_HEADER in reason


def test_stolen_biscuit_with_wrong_key_fails(guard, session, api_key, base_url):
    """A different workload presenting this agent's stolen Biscuit is denied:
    its proof-of-possession is not signed by the token's bound key."""
    from clayseal.identity import ClaySeal

    with ClaySeal(api_key=api_key, base_url=base_url, dev_attestation=True) as other:
        thief = other.identify(
            agent_type="thief", owner="m@x.y", capabilities=TOOL_CAPS
        )
        allowed, reason = guard.authorize_call(
            "search_web",
            biscuit_b64=session.credential.biscuit,
            pop_json=_pop(thief),
        )
    assert allowed is False
    assert "proof-of-possession" in reason or "bound workload key" in reason


def test_pop_for_wrong_server_url_fails(guard, session):
    allowed, _ = guard.authorize_call(
        "search_web",
        biscuit_b64=session.credential.biscuit,
        pop_json=_pop(session, url="https://evil.example.com/mcp"),
    )
    assert allowed is False


def test_replay_cache_makes_proofs_single_use(session):
    """With a replay cache, a captured proof works once and is rejected on
    reuse; a fresh proof for the same session still passes."""
    guard = ToolGuard(
        biscuit_root_public_key=session.credential.biscuit_root_public_key,
        server_url=SERVER_URL,
        replay_cache=InMemoryReplayCache(),
    )
    biscuit = session.credential.biscuit
    pop = _pop(session)
    first = guard.authorize_call("search_web", biscuit_b64=biscuit, pop_json=pop)
    assert first == (True, "authorized")
    replay = guard.authorize_call("search_web", biscuit_b64=biscuit, pop_json=pop)
    assert replay[0] is False
    assert "replay" in replay[1]
    # A distinct, freshly-signed proof is accepted.
    fresh = guard.authorize_call("search_web", biscuit_b64=biscuit, pop_json=_pop(session))
    assert fresh[0] is True


def test_without_replay_cache_a_proof_is_reusable(guard, session):
    """Default (connection-level) behavior: one proof authorizes repeated calls.
    Endpoint-binding still prevents cross-service replay."""
    biscuit = session.credential.biscuit
    pop = _pop(session)
    assert guard.authorize_call("search_web", biscuit_b64=biscuit, pop_json=pop)[0] is True
    assert guard.authorize_call("search_web", biscuit_b64=biscuit, pop_json=pop)[0] is True


def test_garbage_biscuit_fails_closed(guard, session):
    allowed, _ = guard.authorize_call(
        "search_web", biscuit_b64="bm90LWEtYmlzY3VpdA", pop_json=_pop(session)
    )
    assert allowed is False


def test_attenuated_biscuit_loses_dropped_tool(guard, session):
    narrowed = session.attenuate(
        capabilities=[{"resource": "tool", "action": "read_docs"}]
    )
    biscuit = narrowed.credential.biscuit
    pop = _pop(narrowed)
    assert guard.authorize_call("read_docs", biscuit_b64=biscuit, pop_json=pop)[0] is True
    assert guard.authorize_call("search_web", biscuit_b64=biscuit, pop_json=pop)[0] is False


def test_wrong_root_key_denied_right_one_in_rotation_allowed(session):
    wrong = "aa" * 32
    biscuit = session.credential.biscuit
    pop = _pop(session)
    lone_wrong = ToolGuard(biscuit_root_public_key=wrong, server_url=SERVER_URL)
    assert lone_wrong.authorize_call("search_web", biscuit_b64=biscuit, pop_json=pop)[0] is False
    rotating = ToolGuard(
        biscuit_root_public_key=[wrong, session.credential.biscuit_root_public_key],
        server_url=SERVER_URL,
    )
    assert rotating.authorize_call("search_web", biscuit_b64=biscuit, pop_json=pop)[0] is True


def test_capability_mapping_override(session):
    guard = ToolGuard(
        biscuit_root_public_key=session.credential.biscuit_root_public_key,
        capability_for_tool=lambda name: ("mcp", name),
        server_url=SERVER_URL,
    )
    # Credential grants ("tool", ...) so a ("mcp", ...) requirement is denied.
    allowed, _ = guard.authorize_call(
        "search_web", biscuit_b64=session.credential.biscuit, pop_json=_pop(session)
    )
    assert allowed is False
    assert default_tool_capability("x") == ("tool", "x")


# --- FastMCP decorator ---------------------------------------------------------- #
def _enter_request_ctx(headers: dict[str, str]):
    """Simulate the lowlevel MCP server's per-request context with an HTTP
    request carrying the given headers."""
    from mcp.server.lowlevel.server import request_ctx

    fake = SimpleNamespace(request=SimpleNamespace(headers=headers))
    return request_ctx.set(fake)


def _reset_request_ctx(token):
    from mcp.server.lowlevel.server import request_ctx

    request_ctx.reset(token)


def _capability_headers(session, url=SERVER_URL) -> dict[str, str]:
    headers = tool_headers(session, server_url=url)
    headers.pop("Authorization")  # transport auth is the verifier's job
    return headers


def test_require_decorator_allows_and_denies(guard, session):
    @guard.require()
    def search_web(query: str) -> str:
        return f"results for {query}"

    @guard.require()
    def delete_records(table: str) -> str:  # pragma: no cover - must not run
        return "deleted"

    token = _enter_request_ctx(_capability_headers(session))
    try:
        assert search_web(query="clay seals") == "results for clay seals"
        with pytest.raises(CapabilityDeniedError, match="delete_records"):
            delete_records(table="users")
    finally:
        _reset_request_ctx(token)


def test_require_decorator_async_and_no_context(guard, session):
    @guard.require()
    async def read_docs(name: str) -> str:
        return name

    token = _enter_request_ctx(_capability_headers(session))
    try:
        assert asyncio.run(read_docs(name="handbook")) == "handbook"
    finally:
        _reset_request_ctx(token)

    # Outside any request context: fail closed.
    with pytest.raises(CapabilityDeniedError):
        asyncio.run(read_docs(name="handbook"))


def test_require_decorator_enforces_path_scope(auth):
    # The authority block must grant read_file; attenuation then narrows the
    # paths it may touch (attenuation can only remove rights, never add them).
    session = auth.identify(
        agent_type="assistant",
        owner="a@b.c",
        capabilities=[{"resource": "tool", "action": "read_file"}],
    )
    guard = ToolGuard(
        biscuit_root_public_key=session.credential.biscuit_root_public_key,
        server_url=SERVER_URL,
    )
    scoped = session.attenuate(
        path_patterns=["docs/*"],
        denied_paths=["docs/secrets/*"],
    )

    @guard.require(file_path_arg="path")
    def read_file(path: str) -> str:
        return f"contents of {path}"

    token = _enter_request_ctx(_capability_headers(scoped))
    try:
        assert read_file(path="docs/guide.md").startswith("contents")
        with pytest.raises(CapabilityDeniedError):
            read_file(path="docs/secrets/key.pem")
        with pytest.raises(CapabilityDeniedError):
            read_file(path="../etc/passwd")
    finally:
        _reset_request_ctx(token)
