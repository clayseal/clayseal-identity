# Identity-Only Integrations

These helpers make Clay Seal Identity easy to use without adopting the rest of
the stack.

## FastAPI

Protect a tool endpoint with offline JWT/JWKS verification:

```python
from fastapi import Depends, FastAPI
from clayseal.identity.integrations.fastapi import AgentIdentityVerifier

app = FastAPI()
require_agent = AgentIdentityVerifier.dependency(
    jwks=tenant_jwks,
    issuer="clayseal.io",
    audience="tools-api",
)

@app.post("/tool")
def tool(identity = Depends(require_agent)):
    return {"agent_id": identity.agent_id, "agent_type": identity.agent_type}
```

### Offline FastAPI middleware

For lower-risk applications that need verified identity context on every
request, wrap the existing offline verifier in a small middleware. The verifier
checks the token signature, issuer, audience, expiration, and the presence of a
confirmation (`cnf.jkt`) claim when `require_cnf=True`.

```python
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from clayseal.identity.integrations.fastapi import AgentIdentityVerifier

app = FastAPI()

verifier = AgentIdentityVerifier(
    jwks=tenant_jwks,
    issuer="clayseal.io",
    audience="tools-api",
    require_cnf=True,
)

PUBLIC_PATHS = {"/health"}


@app.middleware("http")
async def verify_agent_identity(request: Request, call_next):
    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)

    try:
        identity = verifier(request.headers.get("Authorization", ""))
    except HTTPException as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )

    request.state.agent_identity = identity
    return await call_next(request)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/tool")
def tool(request: Request):
    identity = request.state.agent_identity
    return {
        "agent_id": identity.agent_id,
        "agent_type": identity.agent_type,
    }
```

A missing, malformed, expired, incorrectly issued, or incorrectly targeted
token returns `401`.

> **Security boundary:** `require_cnf=True` verifies that the signed token names
> a holder key; it does not prove that this HTTP requester possesses that key.
> This middleware also cannot detect revocation, so someone who copies a valid
> JWT can replay it until it expires. Treat the resulting identity as a
> reduced-assurance identity label, not as sufficient authorization for a
> sensitive route. Before returning protected data or performing a tool action,
> require fresh request-bound proof-of-possession through `/v1/validate`, or use
> `ToolGuard` (or an equivalent server-side capability check). Only then apply
> application-specific policy, returning `403` when an authenticated caller is
> not authorized.

## MCP clients

Attach the agent's identity to an MCP HTTP transport. Three headers travel
together: the JWT bearer (who the agent is), the Biscuit capability token
(what it may do), and a proof-of-possession of the workload key the tokens
are bound to (so a stolen token authorizes nothing):

```python
from clayseal.identity.integrations.mcp import tool_headers

headers = tool_headers(session, server_url="https://tools.example.com/mcp")
```

The proof carries a freshness timestamp; rebuild headers at least every few
minutes and whenever the endpoint changes. Log structured identity metadata
with `identity_metadata(session)`.

## MCP servers

Protect a FastMCP server (official `mcp` SDK) so only Clay Seal-credentialed
agents connect, and each tool call is authorized against the caller's
capability token. Requires `pip install "clayseal-identity[mcp]"`:

```python
from mcp.server.fastmcp import FastMCP
from clayseal.identity.integrations.mcp_server import (
    ClaySealTokenVerifier, ToolGuard, build_auth_settings,
)

verifier = ClaySealTokenVerifier(
    jwks=tenant_jwks,
    issuer="clayseal.io",
    audience=tenant_id,
)
guard = ToolGuard(
    biscuit_root_public_key=tenant_root_public_hex,
    server_url="https://tools.example.com/mcp",
)
mcp = FastMCP(
    "tools",
    token_verifier=verifier,
    auth=build_auth_settings(
        issuer_url="https://identity.example.com",
        resource_server_url="https://tools.example.com/mcp",
    ),
)

@mcp.tool()
@guard.require()
def search_web(query: str) -> str: ...
```

The transport rejects callers without a valid credential (401 plus RFC 9728
resource metadata, handled by the MCP SDK). Each `@guard.require()` tool then
demands the capability `("tool", <name>)` — grant it when minting
(`capabilities=[{"resource": "tool", "action": "search_web"}]`, or
`"action": "*"` for all tools). Because authorization runs against the
Biscuit, an agent that attenuated itself mid-task is held to the narrowed
token. For file-shaped tools, `@guard.require(file_path_arg="path")` also
enforces the token's `allowed_path`/`denied_path` scope. HTTP transports
only; stdio has neither bearer tokens nor headers.

### Proof-of-possession and replay

The proof-of-possession is signed over this server's endpoint URL, so a proof
presented to one service can't be replayed against another — set `server_url`
on the guard (and give each server its real public URL) to get that binding.
By default each proof is single-use within its freshness window. Clients should
send a fresh proof per request — `tool_headers` mints a new one on every call,
so rebuild headers per request.

The default cache is in-process. For multi-worker servers, pass a shared replay
cache with the same interface:

```python
from clayseal.identity.integrations.mcp_server import ToolGuard, InMemoryReplayCache

guard = ToolGuard(
    biscuit_root_public_key=tenant_root_public_hex,
    server_url="https://tools.example.com/mcp",
    replay_cache=InMemoryReplayCache(),   # replace with Redis/memcached across workers
)
```

Only pass `replay_cache=False` if another layer already enforces single-use
proofs.

See `examples/04_mcp_server.py` for the full flow, including attenuation and
the stolen-token case.

## LangChain / LangGraph

Carry identity through framework metadata and HTTP headers:

```python
from clayseal.identity.integrations.langchain import identity_config

result = runnable.invoke(
    {"question": "What changed?"},
    config=identity_config(session),
)
```

Or wrap a runnable-like object:

```python
from clayseal.identity.integrations.langchain import with_agent_identity

secure_runnable = with_agent_identity(runnable, session)
secure_runnable.invoke({"question": "What changed?"})
```

The helpers do not import LangChain or LangGraph directly. They work with
runnable-like objects that accept a `config` argument.

## OpenClaw and Hermes

Both frameworks speak MCP, so the primary path is the MCP integration above:
protect the tool server with `ToolGuard` (Python) or `@clayseal/verify`
(JavaScript, for OpenClaw plugins), and each tool call is authorized against the
agent's capability token. Framework-specific on-ramps live in
[`integrations/`](../integrations):

- **OpenClaw** — a permission-request-hook recipe using `@clayseal/verify`
  ([`integrations/openclaw`](../integrations/openclaw)).
- **Hermes Agent** — an [agentskills.io](https://agentskills.io) skill that
  gives a Hermes agent a Clay Seal identity
  ([`integrations/hermes`](../integrations/hermes)).

## In-process Python tool guard

For a pure-Python agent that calls local functions directly (no MCP server in
between), `protect_tools` wraps callables so each runs only when the session's
capability token allows it. It works with plain callables and common tool-object
shapes (`invoke`, `ainvoke`, `run`, `call`):

```python
from clayseal.identity.integrations.agent_tools import protect_tools, ToolPermission

tools = protect_tools(
    {
        "email.send": raw_send_email,
        "calendar.write": raw_calendar_writer,
        "file.read": raw_file_reader,
    },
    session,
    permissions={
        "email.send": ToolPermission("email", "send"),
        "calendar.write": ToolPermission("calendar", "write"),
        "file.read": {"resource": "file", "action": "read", "file_path": "/repo/README.md"},
    },
)

tools["email.send"]("alice@example.com", "hello")
```

Generate a reviewable manifest for plugin/skill install screens with
`tools.manifest("support-copilot")` — small JSON listing the required
capabilities. Use this when there is no MCP boundary to hang `ToolGuard` on;
otherwise prefer the MCP path above.

## SDK-only verification

Keep the checks in code. That way the verifier you run in tests is the same one
you run in production.

For HTTP tools, put `AgentIdentityVerifier` at the request boundary. For MCP
servers, use `ClaySealTokenVerifier` and `ToolGuard`. For JavaScript MCP
servers, use `@clayseal/verify`.

When you review an MCP client config, remote servers should use HTTPS,
credentials should come from the agent runtime or secret store rather than a
literal token in the config, and local command servers should not receive broad
environment secrets.
