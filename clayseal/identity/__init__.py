"""ClaySeal - identity for agents (Python SDK).

Quickstart::

    from clayseal.identity import ClaySeal

    auth = ClaySeal(api_key="aa_...", dev_attestation=True)  # localhost demos/tests
    agent = auth.identify(agent_type="researcher", owner="alice@acme.ai",
                          scopes=["db:read"])

    print(agent.token)                 # signed JWT to carry on outbound calls

    result = agent.validate()
    assert result.valid
"""
from __future__ import annotations

from .client import ClaySeal
from .errors import (
    ClaySealError,
    AgentNotFoundError,
    AgentRevokedError,
    BiscuitError,
    CapabilityDeniedError,
    InvalidAPIKeyError,
    InvalidTokenError,
    ProofOfPossessionError,
    TokenExpiredError,
    TransportError,
    TTLOutOfRangeError,
)
from .models import AgentInfo, Credential, ValidationResult
from .profile import AgentIdentityClaims, explain_token, lint_token
from .session import AgentSession
from .verifier import verify_offline
from .diagnostics import (
    DiagnosticFinding,
    doctor_agent_identity_document,
    doctor_token,
    findings_payload,
    preflight_endpoint,
    scan_mcp_config,
)
from .usability import (
    diff_token_payload,
    generate_integration,
    replay_lab_payload,
    whoami_payload,
)
from .adapters import (
    IdentityAdapter,
    IdentityBinding,
    get_identity_adapter,
    list_identity_adapters,
    register_identity_adapter,
)

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
