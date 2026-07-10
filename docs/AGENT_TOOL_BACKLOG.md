# Agent Tool Integration Backlog

Goal: make Clay Seal Identity easy to add to always-on, tool-using agents
without requiring developers to adopt the rest of the Clay Seal stack on day one.

The public wedge should stay narrow:

> Give your local/autonomous agent an identity and a permission boundary around
> tool use.

## Principles

- Prefer the tool boundary agents already have (MCP) over framework rewrites.
- Keep the identity package dependency-light.
- Make permissions visible before an agent runs.
- Fail closed before a tool executes.
- Leave receipts, dynamic mandates, and higher-layer enforcement to the sibling
  packages.

## Shipped

- **MCP server authorization** (the primary path) —
  `clayseal.identity.integrations.mcp_server` (`ToolGuard`,
  `ClaySealTokenVerifier`) and the JavaScript `@clayseal/verify`
  ([`js/clayseal-verify`](../js/clayseal-verify)) authorize each tool call
  against the agent's capability token, with sender-constrained
  proof-of-possession and optional single-use replay protection. See
  [INTEGRATIONS.md](INTEGRATIONS.md).
- **OpenClaw on-ramp** — a permission-request-hook recipe using
  `@clayseal/verify` ([`integrations/openclaw`](../integrations/openclaw)).
- **Hermes on-ramp** — an [agentskills.io](https://agentskills.io) skill that
  gives a Hermes agent a Clay Seal identity
  ([`integrations/hermes`](../integrations/hermes)), plus a draft proposal to
  back Hermes's gateway permission tiers with Clay Seal capabilities.
- **In-process Python tool guard** — `protect_tool` / `protect_tools` and
  `agent_tool_manifest` in `clayseal.identity.integrations.agent_tools`, for
  pure-Python agents that call local callables without an MCP boundary.

## Backlog

### Install-time permission review

Status: planned.

An SDK helper (`review_manifest`) that turns a tool manifest into a reviewable
permission summary, callable from install screens, notebooks, or docs
generators. Not shipped yet.

### More framework shims

Status: planned.

Thin, optional adapters only where they reduce friction beyond MCP — e.g. a
CrewAI tool wrapper or an AutoGPT-style command-provider wrapper. Add on demand.

### Later layers

Status: later.

When the full Clay Seal stack is available, connect the same tool-boundary
checks to layer 2 dynamic mandates/leases and layer 3 signed action receipts.
