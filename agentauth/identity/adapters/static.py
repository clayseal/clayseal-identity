"""Static identity adapter for local tests and non-networked deployments."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentauth.identity.adapters.base import IdentityBinding


@dataclass
class StaticIdentityAdapter:
    name: str = "static"

    def to_binding(
        self, raw: dict[str, Any], *, evidence_verified: bool = True
    ) -> IdentityBinding:
        return IdentityBinding(
            subject_id=str(raw.get("subject_id") or raw.get("sub") or raw.get("agent_id", "")),
            issuer=str(raw.get("issuer") or raw.get("iss") or "static"),
            scopes=list(raw.get("scopes", [])),
            tenant_id=raw.get("tenant_id"),
            owner_ref=raw.get("owner_ref") or raw.get("owner"),
            subject_type=raw.get("subject_type") or raw.get("agent_type"),
            expires_at=raw.get("expires_at") or raw.get("exp"),
            evidence_verified=evidence_verified,
            raw=raw,
        )


adapter = StaticIdentityAdapter()
