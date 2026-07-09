"""Provider-neutral identity adapter contracts for L1-only installs."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class IdentityBinding:
    subject_id: str
    issuer: str
    scopes: list[str] = field(default_factory=list)
    tenant_id: str | None = None
    owner_ref: str | None = None
    subject_type: str | None = None
    expires_at: Any = None
    evidence_verified: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def to_claims(self) -> dict[str, Any]:
        return {
            "sub": self.subject_id,
            "iss": self.issuer,
            "scopes": list(self.scopes),
            "tenant_id": self.tenant_id,
            "owner_ref": self.owner_ref,
            "subject_type": self.subject_type,
            "expires_at": self.expires_at,
            "evidence_verified": self.evidence_verified,
        }


@runtime_checkable
class IdentityAdapter(Protocol):
    name: str

    def to_binding(
        self, raw: dict[str, Any], *, evidence_verified: bool = False
    ) -> IdentityBinding:
        ...
