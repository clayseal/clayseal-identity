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

verifier = ClaySealTokenVerifier(jwks=tenant_jwks, issuer="clayseal.io")
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
By default one proof authorizes repeated calls on the same endpoint, which
suits clients that set auth headers once per session.

If you want each proof to be **single-use**, pass a replay cache; a repeated
proof is then rejected within its freshness window. Clients must send a fresh
proof per request — `tool_headers` mints a new one on every call, so rebuild
headers per request when this is on:

```python
from clayseal.identity.integrations.mcp_server import ToolGuard, InMemoryReplayCache

guard = ToolGuard(
    biscuit_root_public_key=tenant_root_public_hex,
    server_url="https://tools.example.com/mcp",
    replay_cache=InMemoryReplayCache(),   # per-process; back with a shared store across workers
)
```

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

## OpenClaw / Hermes-Style Tool Runtimes

For always-on local agents, start by protecting the tools rather than rewriting
the agent framework. The helper below works with plain callables and common
tool-object shapes such as `invoke`, `ainvoke`, `run`, and `call`.

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

Generate a reviewable manifest for plugin/skill install screens:

```python
manifest = tools.manifest("support-copilot")
```

The manifest is intentionally small JSON:

```json
{
  "profile": "clayseal-agent-tools-v1",
  "name": "support-copilot",
  "required_capabilities": [
    {"resource": "email", "action": "send", "file_path": null}
  ]
}
```

This is the recommended starting point for OpenClaw/Hermes-style agents:
identity at startup, capability checks at the tool boundary, and optional
receipts later through the higher Clay Seal layers.

## SDK-only verification

Keep integration checks in code so the same verifier used in tests is the one used in production. For HTTP tools, add `AgentIdentityVerifier` at the request boundary. For MCP servers, use `ClaySealTokenVerifier` and `ToolGuard`. For JavaScript MCP servers, use `@clayseal/verify`.

When reviewing an MCP client config, make sure remote servers use HTTPS, authorization comes from the agent runtime rather than a literal token in the config, and local command servers do not receive broad environment secrets.
