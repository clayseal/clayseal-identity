"""Registry for L1 identity substitutions."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from clayseal.identity.adapters.base import IdentityAdapter

_ADAPTERS: dict[str, IdentityAdapter] = {}


def register_identity_adapter(adapter: IdentityAdapter) -> None:
    _ADAPTERS[adapter.name] = adapter


def get_identity_adapter(name: str) -> IdentityAdapter:
    _ensure_loaded()
    if name not in _ADAPTERS:
        raise KeyError(f"unknown identity adapter {name!r}; known: {', '.join(sorted(_ADAPTERS))}")
    return _ADAPTERS[name]


def list_identity_adapters() -> list[str]:
    _ensure_loaded()
    return sorted(_ADAPTERS)


def _ensure_loaded() -> None:
    if _ADAPTERS:
        return
    from clayseal.identity.adapters.azure import adapter as azure
    from clayseal.identity.adapters.gcp import adapter as gcp
    from clayseal.identity.adapters.oidc import adapter as oidc
    from clayseal.identity.adapters.spiffe import adapter as spiffe
    from clayseal.identity.adapters.static import adapter as static

    for item in (oidc, spiffe, static, azure, gcp):
        register_identity_adapter(item)
