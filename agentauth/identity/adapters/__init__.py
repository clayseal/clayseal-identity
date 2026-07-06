"""Standalone L1 identity adapter registry.

These adapters normalize common identity systems without importing L2/L3. Higher
layers can consume the resulting claim dictionaries, but identity-only users can
also use them for validation, logging, and local policy decisions.
"""
from __future__ import annotations

from agentauth.identity.adapters.azure import AzureIdentityAdapter
from agentauth.identity.adapters.base import IdentityAdapter, IdentityBinding
from agentauth.identity.adapters.gcp import GcpIdentityAdapter
from agentauth.identity.adapters.oidc import OidcIdentityAdapter
from agentauth.identity.adapters.registry import (
    get_identity_adapter,
    list_identity_adapters,
    register_identity_adapter,
)
from agentauth.identity.adapters.spiffe import SpiffeJwtIdentityAdapter
from agentauth.identity.adapters.static import StaticIdentityAdapter

__all__ = [
    "IdentityAdapter",
    "IdentityBinding",
    "AzureIdentityAdapter",
    "GcpIdentityAdapter",
    "OidcIdentityAdapter",
    "SpiffeJwtIdentityAdapter",
    "StaticIdentityAdapter",
    "get_identity_adapter",
    "list_identity_adapters",
    "register_identity_adapter",
]
