# Agent Tool Integration Backlog

Goal: make Clay Seal Identity easy to add to always-on, tool-using agents
without requiring developers to adopt the rest of the Clay Seal stack on day
one.

The public wedge should stay narrow:

> Give your local/autonomous agent an identity and a permission boundary around
> tool use.

## Principles

- Start with wrappers around existing tools, not framework rewrites.
- Keep the identity package dependency-light.
- Make permissions visible before an agent runs.
- Fail closed before a tool executes.
- Leave receipts, dynamic mandates, and higher-layer enforcement to the sibling
  packages.

## Backlog

### 1. Generic Tool Proxy

Status: done.

Wrap plain Python callables and common tool-object shapes (`invoke`, `ainvoke`,
`run`, `call`) with an `AgentSession.enforce(...)` check before execution.

Developer API:

```python
from clayseal.identity.integrations.agent_tools import protect_tool

send_email = protect_tool(
    raw_send_email,
    session,
    name="email.send",
    resource="email",
    action="send",
)
```

### 2. Skill/Plugin Permission Manifest

Status: done.

Produce a small JSON-serializable manifest that OpenClaw/Hermes-style plugin
runtimes can show during install/review.

```python
manifest = agent_tool_manifest(
    "support-copilot",
    [send_email, search_docs],
)
```

### 3. OpenClaw-Style Example

Status: done.

Add an example showing a persistent local assistant with `email.send`,
`calendar.write`, and `file.read` tools wrapped by Clay Seal.

The example should not import OpenClaw. It should mirror the agent-tool shape so
the integration remains stable even if that project changes internals.

### 4. Hermes-Style Example

Status: planned.

Add an example for a multi-agent/task-runner workflow where a parent agent
delegates a narrower session before handing tools to a subtask.

### 5. Install-Time Permission Review

Status: planned.

Add an SDK helper that turns a tool manifest into a reviewable permission summary. This should be callable from install screens, notebooks, docs generators, or a future UI without requiring a separate executable.

```python
from clayseal.identity.integrations.agent_tools import review_manifest

summary = review_manifest(manifest)
```

### 6. Framework-Specific Shims

Status: planned.

After the generic proxy lands, add thin shims only where they reduce developer
friction:

- OpenClaw skill loader adapter
- Hermes task/tool registry adapter
- CrewAI tool wrapper
- AutoGPT-style command provider wrapper

Each shim should be small and optional.

### 7. Later Layers

Status: later.

When the full Clay Seal stack is available, connect the same proxy points to:

- Layer 2 dynamic mandates and leases.
- Layer 3 signed action receipts.
- UI/tooling that explains blocked actions after the fact.
