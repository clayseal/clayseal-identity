"""GCP service account / workload identity federation normalization."""
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
class GcpIdentityAdapter:
    name: str = "gcp_service_account"

    def to_binding(
        self, raw: dict[str, Any], *, evidence_verified: bool = False
    ) -> IdentityBinding:
        subject = raw.get("sub") or raw.get("email") or raw.get("google.subject")
        return IdentityBinding(
            subject_id=str(subject or ""),
            issuer=str(raw.get("iss", "https://accounts.google.com")),
            scopes=_scopes(raw),
            tenant_id=raw.get("project_id") or raw.get("aud"),
            owner_ref=raw.get("email") or raw.get("service_account_email"),
            subject_type=raw.get("subject_type") or "gcp_service_account",
            expires_at=raw.get("exp"),
            evidence_verified=evidence_verified,
            raw=raw,
        )


adapter = GcpIdentityAdapter()
