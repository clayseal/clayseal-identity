# Framework integrations

Drop-in ways to use Clay Seal identity from agent frameworks. Same primitives:
attested credentials, Biscuit capability tokens, sender-constrained
proof-of-possession.

| Integration | What it is | Where |
| --- | --- | --- |
| **MCP servers** | Verify credentials and authorize each tool call on an official-SDK FastMCP server | `clayseal.identity.integrations.mcp_server` (Python package, `[mcp]` extra) |
| **`@clayseal/verify`** | JS/TS verifier for Node MCP servers, edge functions, and OpenClaw plugins | [`js/clayseal-verify`](../js/clayseal-verify) |
| **OpenClaw** | Authorize tool calls from a plugin's permission-request hook | [`openclaw/`](openclaw) |
| **Hermes Agent** | An [agentskills.io](https://agentskills.io) skill that gives a Hermes agent a Clay Seal identity | [`hermes/skills/clayseal-identity`](hermes/skills/clayseal-identity) |

OpenClaw and Hermes both speak MCP, so a Clay Seal-protected MCP server works
with either.
