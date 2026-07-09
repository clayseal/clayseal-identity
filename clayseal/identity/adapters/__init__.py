"""Standalone L1 identity adapter registry.

These adapters normalize common identity systems without importing L2/L3. Higher
layers can consume the resulting claim dictionaries, but identity-only users can
also use them for validation, logging, and local policy decisions.
"""
from __future__ import annotations

from clayseal.identity.adapters.azure import AzureIdentityAdapter
from clayseal.identity.adapters.base import IdentityAdapter, IdentityBinding
from clayseal.identity.adapters.gcp import GcpIdentityAdapter
from clayseal.identity.adapters.oidc import OidcIdentityAdapter
from clayseal.identity.adapters.registry import (
    get_identity_adapter,
    list_identity_adapters,
    register_identity_adapter,
)
from clayseal.identity.adapters.spiffe import SpiffeJwtIdentityAdapter
from clayseal.identity.adapters.static import StaticIdentityAdapter

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
