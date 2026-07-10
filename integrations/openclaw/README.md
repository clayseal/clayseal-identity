# Clay Seal for OpenClaw

Authorize an [OpenClaw](https://openclaw.ai) agent's tool calls against a Clay
Seal capability token, using [`@clayseal/verify`](../../js/clayseal-verify).

OpenClaw runs a **permission-request hook**: after the model selects a tool and
before the action runs, a plugin can approve, deny, or escalate the call. That
is exactly where Clay Seal belongs. Instead of prompting a human for every
action, approve the calls the agent's credential already permits, and escalate
only what falls outside it:

- Tool call is within the credential's capabilities → **approve** silently.
- Tool call is out of scope → **deny**, or route to a human, with the reason.

The blast radius of a prompt-injected "now delete everything" is bounded by what
the credential grants, not by how convincing the prompt is.

## Install

```bash
npm install @clayseal/verify
```

## Tool plugin with a Clay Seal permission hook

```js
import { authorizeTool } from "@clayseal/verify";

// Loaded once from your Clay Seal tenant config.
const ROOT_PUBLIC_KEY = process.env.CLAYSEAL_BISCUIT_ROOT;   // hex, or an array during rotation
const SERVER_URL = process.env.CLAYSEAL_MCP_URL;             // the tool endpoint this agent calls

/**
 * The agent's Clay Seal credential for this session — set when the agent is
 * provisioned (e.g. from the `clayseal-identity` headers). The biscuit and
 * proof-of-possession authorize each call; refresh them periodically since the
 * proof is time-bound.
 */
function credential() {
  return {
    biscuit: process.env.CLAYSEAL_BISCUIT,
    pop: process.env.CLAYSEAL_POP,
  };
}

export function permissionRequest({ tool }) {
  const { biscuit, pop } = credential();
  const decision = authorizeTool({
    tool,                       // OpenClaw tool name -> capability ("tool", <name>)
    biscuit,
    pop,
    rootPublicKey: ROOT_PUBLIC_KEY,
    serverUrl: SERVER_URL,
  });

  if (decision.allowed) {
    return { decision: "approve" };
  }
  // Out of scope: deny outright, or escalate to a human with the reason.
  return {
    decision: "deny",
    reason: `Clay Seal: ${decision.reason}`,
  };
}
```

Wire `permissionRequest` into your plugin's permission hook per the
[OpenClaw plugin docs](https://docs.openclaw.ai/plugins/tool-plugins). Map tool
names to capabilities however your deployment prefers by passing
`capabilityForTool` to `authorizeTool`.

## Where the credential comes from

The agent gets its Clay Seal credential the same way any client does — from the
identity service via the Python SDK or the `clayseal-identity` CLI — and carries
the biscuit + proof-of-possession into the plugin. Issuance never happens inside
the plugin; this side only verifies.
