"""Dependency-light identity integrations for common agent surfaces."""

from .langchain import identity_config, with_agent_identity
from .mcp import authorization_header, identity_metadata, tool_headers

__all__ = [
    "authorization_header",
    "identity_config",
    "identity_metadata",
    "tool_headers",
    "with_agent_identity",
]
