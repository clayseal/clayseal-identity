from __future__ import annotations

import pytest

from clayseal.identity.errors import CapabilityDeniedError
from clayseal.identity.integrations.agent_tools import (
    ToolPermission,
    agent_tool_manifest,
    protect_tool,
    protect_tools,
)


class FakeSession:
    agent_id = "agent-1"
    agent_type = "desktop-agent"
    owner = "alice@example.com"

    def __init__(self, allowed: set[tuple[str, str]]) -> None:
        self.allowed = allowed
        self.checked: list[tuple[str, str, str | None]] = []

    def enforce(self, resource: str, action: str, *, file_path: str | None = None) -> None:
        self.checked.append((resource, action, file_path))
        if (resource, action) not in self.allowed:
            raise CapabilityDeniedError(
                f"denied {resource}:{action}",
                suggestion="test denial",
            )


def test_protect_tool_enforces_before_callable_execution():
    called = []
    session = FakeSession({("email", "send")})

    def send_email(to: str, body: str) -> str:
        called.append((to, body))
        return "sent"

    tool = protect_tool(send_email, session, name="email.send", resource="email", action="send")

    assert tool("a@example.com", "hello") == "sent"
    assert called == [("a@example.com", "hello")]
    assert session.checked == [("email", "send", None)]


def test_protect_tool_blocks_denied_callable_before_execution():
    called = []
    session = FakeSession(set())

    def delete_file(path: str) -> str:
        called.append(path)
        return "deleted"

    tool = protect_tool(
        delete_file,
        session,
        name="file.delete",
        resource="file",
        action="delete",
        file_path=lambda path: path,
    )

    with pytest.raises(CapabilityDeniedError):
        tool("/tmp/important.txt")

    assert called == []
    assert session.checked == [("file", "delete", "/tmp/important.txt")]


def test_dynamic_file_path_preserves_explicit_permission():
    session = FakeSession({("file", "read")})

    def read_file(path: str) -> str:
        return path

    tool = protect_tool(
        read_file,
        session,
        permission=ToolPermission("file", "read"),
        file_path=lambda path: path,
    )

    assert tool("/repo/README.md") == "/repo/README.md"
    assert session.checked == [("file", "read", "/repo/README.md")]


def test_protect_tool_supports_invoke_run_and_audit_context():
    records = []
    session = FakeSession({("calendar", "write"), ("search", "read")})

    class CalendarTool:
        description = "Create calendar events."

        def invoke(self, payload):
            return {"created": payload["title"]}

    class SearchTool:
        name = "search_docs"

        def run(self, query: str):
            return [query]

    calendar = protect_tool(
        CalendarTool(),
        session,
        name="calendar.write",
        resource="calendar",
        action="write",
        on_call=lambda ctx: records.append(ctx.to_dict()),
    )
    search = protect_tool(SearchTool(), session, permission=("search", "read"))

    assert calendar.invoke({"title": "standup"}) == {"created": "standup"}
    assert search.run("invoice") == ["invoice"]
    assert records[0]["tool_name"] == "calendar.write"
    assert records[0]["agent_id"] == "agent-1"
    assert records[0]["allowed"] is True


@pytest.mark.asyncio
async def test_protect_tool_supports_ainvoke():
    session = FakeSession({("browser", "open")})

    class BrowserTool:
        async def ainvoke(self, url: str):
            return {"url": url}

    tool = protect_tool(BrowserTool(), session, name="browser.open", resource="browser", action="open")

    assert await tool.ainvoke("https://example.com") == {"url": "https://example.com"}


def test_protect_tools_registry_and_manifest_are_json_shaped():
    session = FakeSession({("email", "send"), ("file", "read")})

    def send_email():
        return "sent"

    def read_file(path: str):
        return path

    registry = protect_tools(
        {"email.send": send_email, "file.read": read_file},
        session,
        permissions={
            "email.send": ToolPermission("email", "send"),
            "file.read": {"resource": "file", "action": "read", "file_path": "/repo/README.md"},
        },
    )

    assert registry["email.send"]() == "sent"
    assert registry["file.read"]("/repo/README.md") == "/repo/README.md"

    manifest = registry.manifest(
        "support-copilot",
        description="OpenClaw/Hermes-style local assistant tools.",
    )
    assert manifest["profile"] == "clayseal-agent-tools-v1"
    assert manifest["name"] == "support-copilot"
    assert {"resource": "email", "action": "send", "file_path": None} in manifest[
        "required_capabilities"
    ]
    assert agent_tool_manifest("x", registry.as_dict().values())["tools"][0]["name"]
