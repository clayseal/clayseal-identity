"""Framework-light helpers for protecting agent tools with Clay Seal identity."""
from __future__ import annotations

import inspect
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from clayseal.identity.errors import CapabilityDeniedError

FilePathResolver = Callable[..., str | None]
AuditCallback = Callable[["ToolCallContext"], None]


@dataclass(frozen=True)
class ToolPermission:
    """The Clay Seal capability required before a tool may execute."""

    resource: str
    action: str = "call"
    file_path: str | FilePathResolver | None = None
    description: str = ""


@dataclass(frozen=True)
class ToolCallContext:
    """Small audit object emitted around a protected tool call.

    This is intentionally not a receipt. It is local process context for logs,
    tests, and adapters. Signed receipts belong in the receipts layer.
    """

    tool_name: str
    resource: str
    action: str
    file_path: str | None
    agent_id: str
    agent_type: str
    owner: str
    allowed: bool
    error: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "resource": self.resource,
            "action": self.action,
            "file_path": self.file_path,
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "owner": self.owner,
            "allowed": self.allowed,
            "error": self.error,
            "metadata": dict(self.metadata),
        }


def _tool_name(tool: Any, explicit: str | None = None) -> str:
    if explicit:
        return explicit
    for attr in ("name", "__name__"):
        value = getattr(tool, attr, "")
        if isinstance(value, str) and value:
            return value
    return tool.__class__.__name__


def _description(tool: Any) -> str:
    value = getattr(tool, "description", "")
    if isinstance(value, str) and value:
        return value
    doc = getattr(tool, "__doc__", "") or ""
    return doc.strip().splitlines()[0] if doc.strip() else ""


def _safe_segment(value: str) -> str:
    out = []
    for char in value.lower():
        if char.isalnum() or char in {"-", "_", ".", ":"}:
            out.append(char)
        elif char.isspace() or char == "/":
            out.append("-")
    cleaned = "".join(out).strip("-")
    return cleaned or "tool"


def _permission_from_value(
    value: ToolPermission | Mapping[str, Any] | tuple[str, str] | str | None,
    *,
    tool_name: str,
    default_action: str,
    resource_prefix: str,
) -> ToolPermission:
    if isinstance(value, ToolPermission):
        return value
    if isinstance(value, str):
        return ToolPermission(resource=value, action=default_action)
    if isinstance(value, tuple):
        resource, action = value
        return ToolPermission(resource=str(resource), action=str(action))
    if isinstance(value, Mapping):
        return ToolPermission(
            resource=str(value.get("resource") or f"{resource_prefix}:{_safe_segment(tool_name)}"),
            action=str(value.get("action") or default_action),
            file_path=value.get("file_path"),
            description=str(value.get("description") or ""),
        )
    return ToolPermission(
        resource=f"{resource_prefix}:{_safe_segment(tool_name)}",
        action=default_action,
    )


def _resolve_file_path(permission: ToolPermission, args: tuple[Any, ...], kwargs: dict[str, Any]) -> str | None:
    file_path = permission.file_path
    if callable(file_path):
        return file_path(*args, **kwargs)
    return file_path


def _identity(session: Any) -> dict[str, str]:
    return {
        "agent_id": str(getattr(session, "agent_id", "")),
        "agent_type": str(getattr(session, "agent_type", "")),
        "owner": str(getattr(session, "owner", "")),
    }


def _enforce(session: Any, permission: ToolPermission, file_path: str | None) -> None:
    enforce = getattr(session, "enforce", None)
    if callable(enforce):
        enforce(permission.resource, permission.action, file_path=file_path)
        return

    can = getattr(session, "can", None)
    if callable(can) and can(permission.resource, permission.action, file_path=file_path):
        return

    raise CapabilityDeniedError(
        f"Tool requires {permission.resource}:{permission.action}.",
        code="capability_denied",
        suggestion="Pass an AgentSession with that capability, or attenuate the agent to the intended tool scope.",
    )


class ProtectedTool:
    """Proxy object that enforces a Clay Seal capability before tool execution."""

    def __init__(
        self,
        tool: Any,
        session: Any,
        *,
        name: str | None = None,
        permission: ToolPermission | Mapping[str, Any] | tuple[str, str] | str | None = None,
        resource: str | None = None,
        action: str = "call",
        file_path: str | FilePathResolver | None = None,
        resource_prefix: str = "tool",
        on_call: AuditCallback | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        self.tool = tool
        self.session = session
        self.name = _tool_name(tool, name)
        base_permission = _permission_from_value(
            permission,
            tool_name=self.name,
            default_action=action,
            resource_prefix=resource_prefix,
        )
        if resource is not None or file_path is not None:
            base_permission = ToolPermission(
                resource=resource or base_permission.resource,
                action=base_permission.action,
                file_path=file_path if file_path is not None else base_permission.file_path,
                description=base_permission.description,
            )
        self.permission = base_permission
        self.description = self.permission.description or _description(tool)
        self.on_call = on_call
        self.metadata = dict(metadata or {})

    def _context(self, *, file_path: str | None, allowed: bool, error: str = "") -> ToolCallContext:
        identity = _identity(self.session)
        return ToolCallContext(
            tool_name=self.name,
            resource=self.permission.resource,
            action=self.permission.action,
            file_path=file_path,
            allowed=allowed,
            error=error,
            metadata=self.metadata,
            **identity,
        )

    def _before(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> str | None:
        file_path = _resolve_file_path(self.permission, args, kwargs)
        try:
            _enforce(self.session, self.permission, file_path)
        except Exception as exc:
            if self.on_call is not None:
                self.on_call(self._context(file_path=file_path, allowed=False, error=str(exc)))
            raise
        if self.on_call is not None:
            self.on_call(self._context(file_path=file_path, allowed=True))
        return file_path

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self._before(args, kwargs)
        if not callable(self.tool):
            raise TypeError(f"protected tool {self.name!r} is not callable")
        return self.tool(*args, **kwargs)

    def invoke(self, input: Any = None, **kwargs: Any) -> Any:
        args = () if input is None else (input,)
        self._before(args, kwargs)
        invoke = getattr(self.tool, "invoke", None)
        if callable(invoke):
            return invoke(input, **kwargs)
        if callable(self.tool):
            return self.tool(input, **kwargs)
        raise TypeError(f"protected tool {self.name!r} has no invoke() or __call__()")

    async def ainvoke(self, input: Any = None, **kwargs: Any) -> Any:
        args = () if input is None else (input,)
        self._before(args, kwargs)
        ainvoke = getattr(self.tool, "ainvoke", None)
        if callable(ainvoke):
            return await ainvoke(input, **kwargs)
        invoke = getattr(self.tool, "invoke", None)
        if callable(invoke):
            result = invoke(input, **kwargs)
        elif callable(self.tool):
            result = self.tool(input, **kwargs)
        else:
            raise TypeError(f"protected tool {self.name!r} has no ainvoke(), invoke(), or __call__()")
        if inspect.isawaitable(result):
            return await result
        return result

    def run(self, *args: Any, **kwargs: Any) -> Any:
        self._before(args, kwargs)
        run = getattr(self.tool, "run", None)
        if callable(run):
            return run(*args, **kwargs)
        if callable(self.tool):
            return self.tool(*args, **kwargs)
        raise TypeError(f"protected tool {self.name!r} has no run() or __call__()")

    def call(self, *args: Any, **kwargs: Any) -> Any:
        call = getattr(self.tool, "call", None)
        if callable(call):
            self._before(args, kwargs)
            return call(*args, **kwargs)
        return self.__call__(*args, **kwargs)

    def manifest_entry(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "requires": {
                "resource": self.permission.resource,
                "action": self.permission.action,
                "file_path": None if callable(self.permission.file_path) else self.permission.file_path,
            },
            "metadata": dict(self.metadata),
        }

    def __getattr__(self, name: str) -> Any:
        return getattr(self.tool, name)


class AgentToolProxy:
    """A small registry of protected tools for agent runtimes."""

    def __init__(self, tools: Mapping[str, ProtectedTool]) -> None:
        self.tools = dict(tools)

    def __getitem__(self, name: str) -> ProtectedTool:
        return self.tools[name]

    def get(self, name: str, default: Any = None) -> ProtectedTool | Any:
        return self.tools.get(name, default)

    def as_dict(self) -> dict[str, ProtectedTool]:
        return dict(self.tools)

    def manifest(self, name: str, *, description: str = "", version: str = "0.1.0") -> dict[str, Any]:
        return agent_tool_manifest(name, self.tools.values(), description=description, version=version)


def protect_tool(
    tool: Any,
    session: Any,
    *,
    name: str | None = None,
    permission: ToolPermission | Mapping[str, Any] | tuple[str, str] | str | None = None,
    resource: str | None = None,
    action: str = "call",
    file_path: str | FilePathResolver | None = None,
    resource_prefix: str = "tool",
    on_call: AuditCallback | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> ProtectedTool:
    """Return a tool proxy that checks Clay Seal capabilities before execution."""
    return ProtectedTool(
        tool,
        session,
        name=name,
        permission=permission,
        resource=resource,
        action=action,
        file_path=file_path,
        resource_prefix=resource_prefix,
        on_call=on_call,
        metadata=metadata,
    )


def protect_tools(
    tools: Mapping[str, Any] | Iterable[Any],
    session: Any,
    *,
    permissions: Mapping[str, ToolPermission | Mapping[str, Any] | tuple[str, str] | str] | None = None,
    default_action: str = "call",
    resource_prefix: str = "tool",
    on_call: AuditCallback | None = None,
) -> AgentToolProxy:
    """Protect a mapping/list of tools and return a tiny registry."""
    permissions = permissions or {}
    items = tools.items() if isinstance(tools, Mapping) else ((_tool_name(tool), tool) for tool in tools)
    protected: dict[str, ProtectedTool] = {}
    for name, tool in items:
        protected[str(name)] = protect_tool(
            tool,
            session,
            name=str(name),
            permission=permissions.get(str(name)),
            action=default_action,
            resource_prefix=resource_prefix,
            on_call=on_call,
        )
    return AgentToolProxy(protected)


def agent_tool_manifest(
    name: str,
    tools: Iterable[ProtectedTool],
    *,
    description: str = "",
    version: str = "0.1.0",
) -> dict[str, Any]:
    """Return a JSON-serializable permission manifest for tool/plugin review."""
    entries = [tool.manifest_entry() for tool in tools]
    required = []
    seen = set()
    for entry in entries:
        req = entry["requires"]
        key = (req["resource"], req["action"], req.get("file_path"))
        if key in seen:
            continue
        seen.add(key)
        required.append(req)
    return {
        "profile": "clayseal-agent-tools-v1",
        "name": name,
        "version": version,
        "description": description,
        "tools": entries,
        "required_capabilities": required,
    }
