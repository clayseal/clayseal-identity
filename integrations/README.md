# Framework integrations

Drop-in ways to use Clay Seal identity from popular agent frameworks. Each
builds on the same primitives as the core SDK — attested credentials, Biscuit
capability tokens, and sender-constrained proof-of-possession — so an agent
proves who it is and what it may do on every tool call.

| Integration | What it is | Where |
| --- | --- | --- |
| **MCP servers** | Verify credentials and authorize each tool call on an official-SDK FastMCP server | `clayseal.identity.integrations.mcp_server` (in the Python package, `[mcp]` extra) |
| **`@clayseal/verify`** | JS/TS verifier for Node MCP servers, edge functions, and OpenClaw plugins | [`js/clayseal-verify`](../js/clayseal-verify) |
| **OpenClaw** | Authorize tool calls from a plugin's permission-request hook | [`openclaw/`](openclaw) |
| **Hermes Agent** | An [agentskills.io](https://agentskills.io) skill that gives a Hermes agent a Clay Seal identity | [`hermes/skills/clayseal-identity`](hermes/skills/clayseal-identity) |

The MCP integration is the common core: OpenClaw and Hermes both speak MCP, so a
Clay Seal-protected MCP server works with either without framework-specific
code. The framework packages here are the on-ramps for teams that want a native
fit.

See also `hermes/issue-527-comment.md` — a draft proposal to back Hermes's
gateway permission tiers with Clay Seal capabilities.
