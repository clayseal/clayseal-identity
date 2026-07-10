"""ClaySeal - identity for agents (Python SDK).

Quickstart::

    from clayseal.identity import ClaySeal

    # Point at your Clay Seal identity service. In production the workload's
    # platform (e.g. a SPIRE agent) supplies the attestation document.
    auth = ClaySeal(api_key="aa_...", base_url="https://identity.example.com")
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
from .diagnostics import (
    DiagnosticFinding,
    doctor_agent_identity_document,
    doctor_token,
    findings_payload,
    preflight_endpoint,
    scan_mcp_config,
)
from .errors import (
    AgentNotFoundError,
    AgentRevokedError,
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
from .integrations import (
    AgentToolProxy,
    ProtectedTool,
    ToolCallContext,
    ToolPermission,
    agent_tool_manifest,
    protect_tool,
    protect_tools,
)
from .models import AgentInfo, Credential, ValidationResult
from .profile import AgentIdentityClaims, explain_token, lint_token
from .session import AgentSession
from .usability import (
    diff_token_payload,
    generate_integration,
    replay_lab_payload,
    whoami_payload,
)
from .verifier import verify_offline

__version__ = "0.5.0"

__all__ = [
    "ClaySeal",
    "AgentSession",
    "Credential",
    "AgentInfo",
    "ValidationResult",
    "AgentIdentityClaims",
    "explain_token",
    "lint_token",
    "verify_offline",
    "DiagnosticFinding",
    "doctor_agent_identity_document",
    "doctor_token",
    "findings_payload",
    "preflight_endpoint",
    "scan_mcp_config",
    "diff_token_payload",
    "generate_integration",
    "replay_lab_payload",
    "whoami_payload",
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
