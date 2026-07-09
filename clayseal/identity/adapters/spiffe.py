"""SPIFFE JWT-SVID claim normalization for L1-only installs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from clayseal.identity.adapters.base import IdentityBinding, scopes_from_claims


@dataclass
class SpiffeJwtIdentityAdapter:
    name: str = "spiffe_jwt"

    def to_binding(
        self, raw: dict[str, Any], *, evidence_verified: bool = False
    ) -> IdentityBinding:
        subject = str(raw.get("sub", ""))
        tenant_id = raw.get("tenant_id")
        if tenant_id is None and "/customer/" in subject:
            tenant_id = subject.split("/customer/", 1)[1].split("/", 1)[0]
        return IdentityBinding(
            subject_id=subject,
            issuer=str(raw.get("iss", "spiffe")),
            scopes=scopes_from_claims(raw),
            tenant_id=tenant_id,
            owner_ref=raw.get("owner") or raw.get("email"),
            subject_type=raw.get("agent_type") or raw.get("role"),
            expires_at=raw.get("exp"),
            evidence_verified=evidence_verified,
            raw=raw,
        )


adapter = SpiffeJwtIdentityAdapter()
