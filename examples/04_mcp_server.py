"""04 - Lock down an MCP server with Clay Seal.

An MCP server exposes tools; by default anything that can reach it can call
them. This example protects one with Clay Seal in two moves:

  1. `ClaySealTokenVerifier` — the transport rejects callers without a valid
     Clay Seal credential (the official MCP SDK returns 401s and serves the
     RFC 9728 resource metadata for you).
  2. `ToolGuard` — every tool call is authorized against the agent's Biscuit
     capability token plus a proof-of-possession of the workload key the
     token is bound to. A credential scoped to `tool:search_web` cannot call
     `delete_records`; an agent that *attenuated* its token mid-task is held
     to the narrowed rights; and a stolen token without the agent's key
     authorizes nothing.

Run:  pip install "clayseal-identity[mcp]"  &&  python examples/04_mcp_server.py
"""
from __future__ import annotations

import asyncio

import common
import httpx

from clayseal.identity.integrations.mcp import tool_headers
from clayseal.identity.integrations.mcp_server import (
    ClaySealTokenVerifier,
    ToolGuard,
)

MCP_URL = "https://tools.example.com/mcp"


def main() -> None:
    common.title("ClaySeal + MCP - capability-scoped tool calls")
    auth, _api_key, base_url = common.bootstrap("Acme AI")

    # 1. Identify an agent whose credential grants exactly two tools.
    common.step("Issue a credential scoped to search_web and read_docs")
    session = auth.identify(
        agent_type="assistant",
        owner="alice@acme.ai",
        capabilities=[
            {"resource": "tool", "action": "search_web"},
            {"resource": "tool", "action": "read_docs"},
        ],
    )
    common.info(f"agent_id = {common.code(session.agent_id)}")
    headers = tool_headers(session, server_url=MCP_URL)
    common.detail(f"headers an MCP client sends: {sorted(headers)}")

    # 2. The MCP server's side: a token verifier bound to the tenant JWKS, and
    #    a tool guard bound to the tenant's Biscuit root public key.
    common.step("Configure the server-side verifier and guard")
    claims = session.validate().claims or {}
    tenant_id = claims["customer_id"]
    jwks = httpx.get(f"{base_url}/t/{tenant_id}/jwks.json").json()
    verifier = ClaySealTokenVerifier(jwks=jwks, issuer=claims["iss"])
    guard = ToolGuard(
        biscuit_root_public_key=session.credential.biscuit_root_public_key,
        server_url=MCP_URL,
    )

    #    On a real server this is the whole integration:
    #
    #        mcp = FastMCP("tools", token_verifier=verifier,
    #                      auth=build_auth_settings(issuer_url=..., resource_server_url=...))
    #
    #        @mcp.tool()
    #        @guard.require()
    #        def search_web(query: str) -> str: ...

    # 3. Transport auth: the JWT-SVID is verified offline against the JWKS.
    common.step("Verify the bearer token (what the transport does on every request)")
    access = asyncio.run(verifier.verify_token(session.token))
    if access is not None:
        common.allow(f"401-gate passed: client_id={access.client_id}")
    tampered = session.token[:-4] + "AAAA"
    if asyncio.run(verifier.verify_token(tampered)) is None:
        common.deny("tampered token rejected at the transport (401)")

    # 4. Per-tool authorization: the Biscuit + proof-of-possession decide.
    common.step("Authorize tool calls against the capability token")
    biscuit = session.credential.biscuit
    pop = headers.get("X-ClaySeal-PoP")
    for tool in ("search_web", "read_docs", "delete_records"):
        allowed, reason = guard.authorize_call(tool, biscuit_b64=biscuit, pop_json=pop)
        if allowed:
            common.allow(f"{tool}: allowed")
        else:
            common.deny(f"{tool}: denied")

    # 5. Attenuation is honored: the agent narrows itself to read_docs only,
    #    and the tool it could call a moment ago is now out of scope.
    common.step("Attenuate the session to read_docs only, then retry search_web")
    narrowed = session.attenuate(
        capabilities=[{"resource": "tool", "action": "read_docs"}]
    )
    n_headers = tool_headers(narrowed, server_url=MCP_URL)
    n_biscuit = narrowed.credential.biscuit
    n_pop = n_headers.get("X-ClaySeal-PoP")
    for tool in ("read_docs", "search_web"):
        allowed, _ = guard.authorize_call(tool, biscuit_b64=n_biscuit, pop_json=n_pop)
        if allowed:
            common.allow(f"{tool}: still allowed")
        else:
            common.deny(f"{tool}: denied after attenuation")

    # 6. Sender-constraint: the capability token alone (say, exfiltrated from
    #    a log) is useless without the workload key that signs the proof.
    common.step("A stolen Biscuit without the workload key is denied")
    allowed, _ = guard.authorize_call("search_web", biscuit_b64=biscuit, pop_json=None)
    common.deny("search_web with token but no proof-of-possession: denied")

    common.title("Done - the server enforces exactly what the credential grants")


if __name__ == "__main__":
    main()
