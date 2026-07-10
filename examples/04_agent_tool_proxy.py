"""OpenClaw/Hermes-style tool protection without framework imports.

Run this after you have a real AgentSession from Clay Seal. The tiny
DemoSession below only keeps the example self-contained; production code should
pass the session returned by ``ClaySeal.identify(...)``.
"""
from __future__ import annotations

import common

from clayseal.identity.errors import CapabilityDeniedError
from clayseal.identity.integrations.agent_tools import ToolPermission, protect_tools


class DemoSession:
    agent_id = "agent-demo"
    agent_type = "local-assistant"
    owner = "alice@example.com"

    def __init__(self, allowed: set[tuple[str, str]]) -> None:
        self.allowed = allowed

    def enforce(self, resource: str, action: str, *, file_path: str | None = None) -> None:
        print(f"checking {resource}:{action}" + (f" for {file_path}" if file_path else ""))
        if (resource, action) not in self.allowed:
            raise CapabilityDeniedError(
                f"Capability token does not allow {resource}:{action}.",
                suggestion="Start the agent with a narrower/wider Clay Seal capability set.",
            )


def send_email(to: str, body: str) -> str:
    return f"queued email to {to}: {body}"


def read_file(path: str) -> str:
    return f"pretend contents of {path}"


def main() -> None:
    common.title("ClaySeal - Agent Tool Proxy")
    session = DemoSession({("email", "send"), ("file", "read")})
    common.step("Wrap OpenClaw/Hermes-style tools with Clay Seal permissions")
    tools = protect_tools(
        {
            "email.send": send_email,
            "file.read": read_file,
        },
        session,
        permissions={
            "email.send": ToolPermission("email", "send"),
            "file.read": ToolPermission("file", "read", file_path=lambda path: path),
        },
    )

    common.step("Run allowed tools")
    common.info(tools["email.send"]("alice@example.com", "hello from the agent"))
    common.info(tools["file.read"]("/repo/README.md"))
    common.step("Review the install-time permission manifest")
    common.detail(str(tools.manifest("local-assistant")))


if __name__ == "__main__":
    main()
