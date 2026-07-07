"""OIDC/OAuth2 claim normalization for L1-only installs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentauth.identity.adapters.base import IdentityBinding


def _scopes(raw: dict[str, Any]) -> list[str]:
    scope = raw.get("scope")
    if isinstance(scope, str):
        return scope.split()
    return list(raw.get("scopes", []))


@dataclass
class OidcIdentityAdapter:
    name: str = "oidc"

    def to_binding(
        self, raw: dict[str, Any], *, evidence_verified: bool = False
    ) -> IdentityBinding:
        return IdentityBinding(
            subject_id=str(raw.get("sub", "")),
            issuer=str(raw.get("iss", "oidc")),
            scopes=_scopes(raw),
            tenant_id=raw.get("tenant") or raw.get("tid") or raw.get("org_id"),
            owner_ref=raw.get("email") or raw.get("preferred_username"),
            subject_type=raw.get("role") or raw.get("agent_type"),
            expires_at=raw.get("exp"),
            evidence_verified=evidence_verified,
            raw=raw,
        )


adapter = OidcIdentityAdapter()
