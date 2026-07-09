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

## MCP HTTP Transports

Attach a Clay Seal identity token as a bearer credential:

```python
from clayseal.identity.integrations.mcp import tool_headers

headers = tool_headers(session)
```

Log structured identity metadata:

```python
from clayseal.identity.integrations.mcp import identity_metadata

metadata = identity_metadata(session)
```

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

## Endpoint Preflight

Before wiring a tool server into an agent, run:

```bash
clayseal-identity preflight http://localhost:8000/tool
```

The preflight command checks whether missing and malformed identity are rejected.

## Starter Snippets

For a quick integration skeleton:

```bash
clayseal-identity generate fastapi
clayseal-identity generate mcp
clayseal-identity generate gha
clayseal-identity generate express
```

These are small starter snippets, not production policy. They are meant to get
the request boundary correct quickly so you can then add issuer, JWKS, audience,
and deployment-specific constraints.

## MCP Config Scan

For MCP client configs:

```bash
clayseal-identity scan-mcp mcp-config.json
```

This does not replace a security review, but it catches common identity smells:
plain HTTP remote servers, missing Authorization headers, local command servers,
and secrets passed through environment variables.
