"""Clay Seal authorization for MCP servers (server side).

Two pieces, matching how the official ``mcp`` Python SDK splits transport
authentication from per-call authorization:

- :class:`ClaySealTokenVerifier` plugs into ``FastMCP(token_verifier=...)`` and
  verifies the agent's JWT-SVID offline against the tenant JWKS. Requests
  without a valid credential are rejected at the transport with a 401 before
  any tool runs, and the SDK serves the RFC 9728 protected-resource metadata.

- :class:`ToolGuard` authorizes each tool call against the agent's **Biscuit
  capability token** plus a **proof-of-possession** of the workload key the
  token is bound to (both sent as headers by
  ``clayseal.identity.integrations.mcp.tool_headers``). Because the Biscuit is
  what gets authorized, an agent that attenuated its rights mid-task is held to
  the narrowed token; because the Biscuit is sender-constrained, a stolen
  token without the agent's Ed25519 key authorizes nothing.

Quickstart::

    from mcp.server.fastmcp import FastMCP
    from clayseal.identity.integrations.mcp_server import (
        ClaySealTokenVerifier, ToolGuard, build_auth_settings,
    )

    verifier = ClaySealTokenVerifier(jwks=jwks, issuer="clayseal.io", audience=tenant_id)
    guard = ToolGuard(biscuit_root_public_key=root_public_hex)
    mcp = FastMCP(
        "tools",
        token_verifier=verifier,
        auth=build_auth_settings(
            issuer_url="https://identity.example.com",
            resource_server_url="https://tools.example.com/mcp",
        ),
    )

    @mcp.tool()
    @guard.require()          # capability ("tool", "search_web") — or override
    def search_web(query: str) -> str: ...

Requires the ``mcp`` extra: ``pip install "clayseal-identity[mcp]"``. HTTP
transports only (streamable HTTP / SSE); stdio has neither bearer tokens nor
headers to authorize.
"""
from __future__ import annotations

import functools
import inspect
import json
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any, Protocol

try:
    from mcp.server.auth.provider import AccessToken
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.lowlevel.server import request_ctx
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "clayseal.identity.integrations.mcp_server requires the official MCP "
        'SDK. Install it with: pip install "clayseal-identity[mcp]"'
    ) from exc

from clayseal.identity._capabilities import PopProof, authorize_biscuit
from clayseal.identity.errors import CapabilityDeniedError, ClaySealError
from clayseal.identity.verifier import verify_offline

from .mcp import BISCUIT_HEADER, POP_HEADER

__all__ = [
    "BISCUIT_HEADER",
    "POP_HEADER",
    "ClaySealTokenVerifier",
    "InMemoryReplayCache",
    "ReplayCache",
    "ToolGuard",
    "build_auth_settings",
    "default_tool_capability",
]

# Proof-of-possession freshness window; matches workload_keys.verify_request_pop.
_POP_MAX_AGE_SECONDS = 300


class ReplayCache(Protocol):
    """Records proof-of-possession ``jti`` values so each proof is single-use.

    ``store_if_new`` returns ``True`` the first time a ``jti`` is seen (and
    records it until ``expires_at``, an epoch second) and ``False`` on any
    repeat — a replay. Implement this over a shared store (Redis, memcached)
    for multi-process deployments.
    """

    def store_if_new(self, jti: str, expires_at: int) -> bool: ...


class InMemoryReplayCache:
    """Single-process :class:`ReplayCache`. Each proof ``jti`` is accepted once
    within its freshness window; expired entries are pruned lazily.

    Per-process only — like the rate limiter, it does not span workers. For a
    multi-process deployment, supply a shared-store cache with the same
    interface.
    """

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def store_if_new(self, jti: str, expires_at: int) -> bool:
        now = int(time.time())
        with self._lock:
            if self._seen:
                for key, exp in list(self._seen.items()):
                    if exp <= now:
                        del self._seen[key]
            if jti in self._seen:
                return False
            self._seen[jti] = expires_at
            return True


def default_tool_capability(tool_name: str) -> tuple[str, str]:
    """Map an MCP tool to the capability it requires: ``("tool", <name>)``.

    A credential minted with ``{"resource": "tool", "action": "search_web"}``
    can call that one tool; ``{"resource": "tool", "action": "*"}`` can call
    any tool on the server.
    """
    return ("tool", tool_name)


class ClaySealTokenVerifier:
    """``mcp`` SDK ``TokenVerifier`` that verifies Clay Seal JWT-SVIDs offline.

    ``jwks`` is the tenant JWKS document (``GET /t/{tenant}/jwks.json``) or a
    zero-argument callable returning it, so callers can plug in a cache that
    refreshes on rotation.
    """

    def __init__(
        self,
        *,
        jwks: Mapping[str, Any] | Callable[[], Mapping[str, Any]],
        issuer: str,
        audience: str | Iterable[str],
        leeway: int | float = 0,
    ) -> None:
        self._jwks = jwks
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway

    def _jwks_document(self) -> Mapping[str, Any]:
        return self._jwks() if callable(self._jwks) else self._jwks

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = verify_offline(
                token,
                jwks=self._jwks_document(),
                issuer=self._issuer,
                audience=self._audience,
                leeway=self._leeway,
            )
        except ClaySealError:
            return None
        return AccessToken(
            token=token,
            client_id=str(claims.get("agent_id", claims.get("sub", ""))),
            scopes=[str(s) for s in claims.get("scope", [])],
            expires_at=claims.get("exp"),
            subject=str(claims.get("sub", "")),
            claims=claims,
        )


class ToolGuard:
    """Per-tool capability authorization against the agent's Biscuit.

    ``biscuit_root_public_key`` is the tenant's Biscuit root public key (hex),
    or several of them during rotation — authorization succeeds if any key
    verifies the token. ``capability_for_tool`` overrides the default
    ``("tool", <name>)`` mapping.

    Clay Seal capability tokens are sender-constrained: the tool call must
    carry a proof-of-possession (the ``X-ClaySeal-PoP`` header built by
    ``clayseal.identity.integrations.mcp.tool_headers``) signed by the
    workload key the Biscuit is bound to. Set ``server_url`` to pin the proof
    to this server's public MCP endpoint, which is what stops a proof captured
    by one service from being replayed against another.

    By default an in-process replay cache makes each proof **single-use** within
    its freshness window, closing same-endpoint replay. For a multi-process
    deployment, pass a shared-store cache with the same interface. Pass
    ``replay_cache=False`` only when another layer already enforces single-use
    proofs.
    """

    def __init__(
        self,
        *,
        biscuit_root_public_key: str | Iterable[str],
        capability_for_tool: Callable[[str], tuple[str, str]] | None = None,
        biscuit_header: str = BISCUIT_HEADER,
        pop_header: str = POP_HEADER,
        server_url: str | None = None,
        replay_cache: ReplayCache | bool | None = None,
    ) -> None:
        keys = (
            [biscuit_root_public_key]
            if isinstance(biscuit_root_public_key, str)
            else list(biscuit_root_public_key)
        )
        if not keys:
            raise ValueError("biscuit_root_public_key must not be empty")
        self._root_keys = keys
        self._capability_for_tool = capability_for_tool or default_tool_capability
        self._biscuit_header = biscuit_header
        self._pop_header = pop_header
        self._server_url = server_url
        if replay_cache is True:
            raise ValueError("replay_cache=True is ambiguous; pass a ReplayCache or omit it")
        self._replay_cache = (
            None
            if replay_cache is False
            else replay_cache
            if replay_cache is not None
            else InMemoryReplayCache()
        )

    # --- framework-agnostic core ------------------------------------------- #
    def authorize_call(
        self,
        tool_name: str,
        *,
        biscuit_b64: str | None,
        pop_json: str | None = None,
        file_path: str | None = None,
    ) -> tuple[bool, str]:
        """Decide whether ``biscuit_b64`` + ``pop_json`` authorize ``tool_name``.

        Fail-closed: no Biscuit or no valid proof-of-possession means no tool
        call, whatever the JWT says.
        """
        return self._authorize_operation(
            self._capability_for_tool(tool_name),
            biscuit_b64=biscuit_b64,
            pop_json=pop_json,
            file_path=file_path,
        )

    # --- FastMCP decorator -------------------------------------------------- #
    def require(
        self,
        resource: str | None = None,
        action: str | None = None,
        *,
        file_path_arg: str | None = None,
    ) -> Callable:
        """Decorate a FastMCP tool so it runs only when the caller's Biscuit
        authorizes it.

        By default the required capability comes from ``capability_for_tool``
        applied to the function name; pass ``resource``/``action`` to pin it
        explicitly. ``file_path_arg`` names the tool argument holding a file
        path, so path-scoped Biscuits (``allowed_path``/``denied_path`` facts)
        are enforced on file tools.

        Apply **under** ``@mcp.tool()`` (closest to the function), so the check
        runs on every call.
        """

        def decorate(fn: Callable) -> Callable:
            tool_name = fn.__name__
            explicit = (resource, action) if resource and action else None

            def check(kwargs: dict[str, Any]) -> None:
                biscuit = _header_from_request(self._biscuit_header)
                pop_json = _header_from_request(self._pop_header)
                file_path = kwargs.get(file_path_arg) if file_path_arg else None
                operation = explicit or self._capability_for_tool(tool_name)
                allowed, reason = self._authorize_operation(
                    operation, biscuit_b64=biscuit, pop_json=pop_json, file_path=file_path
                )
                if not allowed:
                    raise CapabilityDeniedError(
                        f"Tool '{tool_name}' denied: {reason}",
                        suggestion=(
                            "Mint or attenuate the agent's credential with the "
                            f"capability {operation!r}."
                        ),
                    )

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    check(kwargs)
                    return await fn(*args, **kwargs)

                return async_wrapper

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                check(kwargs)
                return fn(*args, **kwargs)

            return wrapper

        return decorate

    def _authorize_operation(
        self,
        operation: tuple[str, str],
        *,
        biscuit_b64: str | None,
        pop_json: str | None,
        file_path: str | None,
    ) -> tuple[bool, str]:
        if not biscuit_b64:
            return (
                False,
                f"no capability token presented (send the {self._biscuit_header} "
                "header; clayseal.identity.integrations.mcp.tool_headers adds it)",
            )
        pop = _parse_pop(pop_json)
        if pop is None:
            return (
                False,
                f"no proof-of-possession presented (send the {self._pop_header} "
                "header; pass server_url to tool_headers to sign one)",
            )
        last_reason = "capability token could not be verified"
        for root in self._root_keys:
            try:
                decision = authorize_biscuit(
                    token_b64=biscuit_b64,
                    root_public_hex=root,
                    operation=operation,
                    pop=pop,
                    pop_binds_operation=False,
                    expected_htm="POST",
                    expected_htu=self._server_url,
                    file_path=file_path,
                )
            except Exception:  # noqa: BLE001
                continue
            if decision.get("allowed"):
                # The proof's signature is valid and it authorizes the call.
                # If single-use is on, reject a proof we've already accepted
                # (a replay) — checked only now so an attacker cannot fill the
                # cache with unsigned jti values.
                if self._replay_cache is not None and not self._replay_cache.store_if_new(
                    pop.jti, int(pop.iat) + _POP_MAX_AGE_SECONDS
                ):
                    return False, "proof-of-possession already used (replay detected)"
                return True, "authorized"
            last_reason = str(decision.get("reason", "denied"))
        return False, last_reason


def _parse_pop(pop_json: str | None) -> PopProof | None:
    if not pop_json:
        return None
    try:
        raw = json.loads(pop_json)
        return PopProof(
            challenge=str(raw["challenge"]),
            signature_b64=str(raw["signature_b64"]),
            pubkey_pem=str(raw["pubkey_pem"]),
            htm=str(raw["htm"]),
            htu=str(raw["htu"]),
            ath=str(raw["ath"]),
            iat=int(raw["iat"]),
            jti=str(raw["jti"]),
        )
    except (ValueError, KeyError, TypeError):
        return None


def _header_from_request(header_name: str) -> str | None:
    """Read a header from the current MCP request, if any."""
    try:
        ctx = request_ctx.get()
    except LookupError:
        return None
    request = getattr(ctx, "request", None)
    headers = getattr(request, "headers", None)
    if headers is None:
        return None
    return headers.get(header_name)


def build_auth_settings(
    *,
    issuer_url: str,
    resource_server_url: str,
    required_scopes: list[str] | None = None,
) -> AuthSettings:
    """RFC 9728 resource-server settings for ``FastMCP(auth=...)``.

    ``issuer_url`` is the Clay Seal identity service (the authorization
    server clients are pointed at); ``resource_server_url`` is this MCP
    server's public URL.
    """
    return AuthSettings(
        issuer_url=issuer_url,
        resource_server_url=resource_server_url,
        required_scopes=required_scopes,
    )
