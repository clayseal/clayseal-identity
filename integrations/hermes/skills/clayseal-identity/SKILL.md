---
name: clayseal-identity
description: Give a Hermes agent a verifiable Clay Seal identity and call Clay Seal-protected MCP servers. Use when the agent must authenticate to a tool server, present scoped capabilities, narrow its own permissions for a task, or when a task mentions Clay Seal, agent identity, capability tokens, or "attested" tool access.
license: MIT
---

# Clay Seal identity for Hermes

[Clay Seal](https://clayseal.com) gives an agent a short-lived, attested
identity and a **capability token** that says exactly which tools it may call.
Servers verify both offline, so the agent proves who it is and what it is
allowed to do on every request — and can narrow its own rights for a specific
task.

Use this skill to:

- get a Clay Seal credential for this agent, and
- attach it to outbound calls to a Clay Seal-protected MCP server (or any tool
  gateway that verifies Clay Seal headers).

## Setup

This skill needs the Clay Seal SDK and two config values.

Required environment variables:

- `CLAYSEAL_BASE_URL` — the identity service URL (e.g. `https://identity.acme.ai`).
- `CLAYSEAL_API_KEY` — this tenant's API key (`cs_...`).

Install the SDK once:

```bash
pip install "clayseal-identity"
```

## Get a credential

Run `scripts/identify.py` to mint a credential and print the headers to send.
Pass the capabilities the task needs — each is a `resource:action` pair, and
tool calls map to `tool:<tool_name>`:

```bash
python scripts/identify.py \
  --owner "$(whoami)@acme.ai" \
  --capability tool:search_web \
  --capability tool:read_docs \
  --server-url https://tools.acme.ai/mcp
```

It prints a JSON object of HTTP headers (`Authorization`, `X-ClaySeal-Biscuit`,
`X-ClaySeal-PoP`). Send those headers on requests to the tool server. Rebuild
them at least every few minutes — the proof-of-possession is time-bound.

## Narrow rights for a task (recommended)

Grant the agent broad capabilities once, then **attenuate** down to just what a
specific task needs before doing risky work. A narrowed token can never regain
dropped rights, so a prompt-injected instruction to call an out-of-scope tool
is refused by the server, not by the agent's own judgement:

```bash
python scripts/identify.py \
  --owner "$(whoami)@acme.ai" \
  --capability tool:read_docs \
  --path "docs/*" --deny-path "docs/secrets/*" \
  --server-url https://tools.acme.ai/mcp
```

## Notes

- The agent's key never leaves the machine; only the signed credential and a
  proof-of-possession are sent. A token copied from a log is useless without
  the key.
- If a tool call comes back `403` with a Clay Seal reason, the credential does
  not grant that capability — mint one that does, or ask the operator to widen
  the tenant's grants. Do not retry the same call.
- `scripts/identify.py --help` lists every option.
