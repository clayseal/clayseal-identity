"""LangChain/LangGraph identity helpers without a hard dependency on either."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .mcp import authorization_header, identity_metadata


def identity_config(session_or_token: Any, config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return a LangChain/LangGraph config dict carrying identity metadata.

    Frameworks preserve ``metadata`` through traces/callbacks, and many tool
    wrappers accept ``headers`` for HTTP calls. Callers can pass the returned
    config to ``invoke``/``ainvoke``/graph execution.
    """
    out = dict(config or {})
    metadata = dict(out.get("metadata") or {})
    metadata.update(identity_metadata(session_or_token))
    out["metadata"] = metadata
    headers = dict(out.get("headers") or {})
    headers.update(authorization_header(session_or_token))
    out["headers"] = headers
    return out


class IdentityRunnable:
    """Tiny wrapper that injects identity config into runnable-like objects."""

    def __init__(self, runnable: Any, session_or_token: Any) -> None:
        self.runnable = runnable
        self.session_or_token = session_or_token

    def invoke(self, input: Any, config: Mapping[str, Any] | None = None, **kwargs: Any) -> Any:
        return self.runnable.invoke(input, config=identity_config(self.session_or_token, config), **kwargs)

    async def ainvoke(
        self, input: Any, config: Mapping[str, Any] | None = None, **kwargs: Any
    ) -> Any:
        return await self.runnable.ainvoke(
            input, config=identity_config(self.session_or_token, config), **kwargs
        )

    def batch(self, inputs: list[Any], config: Mapping[str, Any] | None = None, **kwargs: Any) -> Any:
        return self.runnable.batch(inputs, config=identity_config(self.session_or_token, config), **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.runnable, name)


def with_agent_identity(runnable: Any, session_or_token: Any) -> IdentityRunnable:
    """Wrap a runnable-like object so invoke/ainvoke/batch carry identity."""
    return IdentityRunnable(runnable, session_or_token)
