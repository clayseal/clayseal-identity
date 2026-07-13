"""ClaySeal - identity for agents (Python SDK).

Quickstart::

    from clayseal.identity import ClaySeal

    # Point at your Clay Seal identity service. In production the workload's
    # platform (e.g. a SPIRE agent) supplies the attestation document.
    auth = ClaySeal(api_key="cs_...", base_url="https://identity.example.com")
    agent = auth.identify(agent_type="researcher", owner="alice@acme.ai",
                          scopes=["db:read"])

    print(agent.token)                 # signed JWT to carry on outbound calls
    assert agent.validate().valid

For a self-contained local demo (no platform attestation), run against a
localhost backend with ``ClaySeal(..., dev_attestation=True)`` — see ``examples/``
and the README. Dev attestation is refused in production.
"""
from __future__ import annotations

from .adapters import (
    IdentityAdapter,
    IdentityBinding,
    get_identity_adapter,
    list_identity_adapters,
    register_identity_adapter,
)
from .client import ClaySeal
from .errors import (
    AgentNotFoundError,
    AgentRevokedError,
    APIKeyScopeError,
    BiscuitError,
    CapabilityDeniedError,
    ClaySealError,
    InvalidAPIKeyError,
    InvalidTokenError,
    ProofOfPossessionError,
    TokenExpiredError,
    TransportError,
    TTLOutOfRangeError,
)
from .inspector import TokenInspection, inspect_token
from .integrations import (
    AgentToolProxy,
    ProtectedTool,
    ToolCallContext,
    ToolPermission,
    agent_tool_manifest,
    protect_tool,
    protect_tools,
)
from .models import AgentInfo, ApiKeyInfo, Credential, ValidationResult
from .profile import AgentIdentityClaims
from .session import AgentSession
from .verifier import verify_offline

__version__ = "0.6.1"

__all__ = [
    "ClaySeal",
    "AgentSession",
    "Credential",
    "AgentInfo",
    "ApiKeyInfo",
    "ValidationResult",
    "AgentIdentityClaims",
    "TokenInspection",
    "inspect_token",
    "verify_offline",
    "IdentityAdapter",
    "IdentityBinding",
    "get_identity_adapter",
    "list_identity_adapters",
    "register_identity_adapter",
    "AgentToolProxy",
    "ProtectedTool",
    "ToolCallContext",
    "ToolPermission",
    "agent_tool_manifest",
    "protect_tool",
    "protect_tools",
    "ClaySealError",
    "TransportError",
    "InvalidAPIKeyError",
    "APIKeyScopeError",
    "InvalidTokenError",
    "TokenExpiredError",
    "AgentRevokedError",
    "AgentNotFoundError",
    "TTLOutOfRangeError",
    "BiscuitError",
    "ProofOfPossessionError",
    "CapabilityDeniedError",
    "__version__",
]
