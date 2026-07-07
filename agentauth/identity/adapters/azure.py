"""Azure AD / workload identity claim normalization for L1-only installs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentauth.identity.adapters.base import IdentityBinding


def _scopes(raw: dict[str, Any]) -> list[str]:
    scope = raw.get("scp") or raw.get("scope")
    scopes = scope.split() if isinstance(scope, str) else list(raw.get("scopes", []))
    return scopes + [str(role) for role in raw.get("roles", [])]


@dataclass
class AzureIdentityAdapter:
    name: str = "azure_ad"

    def to_binding(
        self, raw: dict[str, Any], *, evidence_verified: bool = False
    ) -> IdentityBinding:
        subject = raw.get("oid") or raw.get("sub") or raw.get("appid") or raw.get("azp")
        return IdentityBinding(
            subject_id=str(subject or ""),
            issuer=str(raw.get("iss", "azure_ad")),
            scopes=_scopes(raw),
            tenant_id=raw.get("tid") or raw.get("tenant_id"),
            owner_ref=raw.get("preferred_username") or raw.get("upn") or raw.get("appid"),
            subject_type=raw.get("idtyp") or raw.get("agent_type") or "azure_workload",
            expires_at=raw.get("exp"),
            evidence_verified=evidence_verified,
            raw=raw,
        )


adapter = AzureIdentityAdapter()
