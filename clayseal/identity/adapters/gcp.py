"""GCP service account / workload identity federation normalization."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from clayseal.identity.adapters.base import IdentityBinding, scopes_from_claims


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
            scopes=scopes_from_claims(raw),
            tenant_id=raw.get("project_id") or raw.get("aud"),
            owner_ref=raw.get("email") or raw.get("service_account_email"),
            subject_type=raw.get("subject_type") or "gcp_service_account",
            expires_at=raw.get("exp"),
            evidence_verified=evidence_verified,
            raw=raw,
        )


adapter = GcpIdentityAdapter()
