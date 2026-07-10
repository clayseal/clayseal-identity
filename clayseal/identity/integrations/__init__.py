"""Dependency-light identity integrations for common agent surfaces."""

from .agent_tools import (
    AgentToolProxy,
    ProtectedTool,
    ToolCallContext,
    ToolPermission,
    agent_tool_manifest,
    protect_tool,
    protect_tools,
)
from .langchain import identity_config, with_agent_identity
from .mcp import authorization_header, identity_metadata, tool_headers

__all__ = [
    "AgentToolProxy",
    "ProtectedTool",
    "ToolCallContext",
    "ToolPermission",
    "agent_tool_manifest",
    "authorization_header",
    "identity_config",
    "identity_metadata",
    "protect_tool",
    "protect_tools",
    "tool_headers",
    "with_agent_identity",
]
