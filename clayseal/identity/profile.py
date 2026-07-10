"""Agent identity profile helpers.

A dependency-light, normalized view of Clay Seal agent identity claims used by
the SDK and the framework integrations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PROFILE_NAME = "clayseal-agent-identity-v1"


@dataclass
class AgentIdentityClaims:
    """Normalized view of Clay Seal agent identity claims."""

    subject: str
    issuer: str
    audience: str | list[str] | None
    agent_id: str = ""
    agent_type: str = ""
    principal: str = ""
    scopes: list[str] = field(default_factory=list)
    selectors: list[str] = field(default_factory=list)
    expires_at: int | None = None
    issued_at: int | None = None
    confirmation_thumbprint: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> AgentIdentityClaims:
        cnf = claims.get("cnf") or {}
        return cls(
            subject=str(claims.get("sub") or ""),
            issuer=str(claims.get("iss") or ""),
            audience=claims.get("aud"),
            agent_id=str(claims.get("agent_id") or ""),
            agent_type=str(claims.get("agent_type") or ""),
            principal=str(claims.get("owner") or claims.get("principal") or ""),
            scopes=list(claims.get("scope") or claims.get("scopes") or []),
            selectors=list(claims.get("selectors") or []),
            expires_at=claims.get("exp"),
            issued_at=claims.get("iat"),
            confirmation_thumbprint=str(cnf.get("jkt") or ""),
            raw=dict(claims),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": PROFILE_NAME,
            "subject": self.subject,
            "issuer": self.issuer,
            "audience": self.audience,
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "principal": self.principal,
            "scopes": list(self.scopes),
            "selectors": list(self.selectors),
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "confirmation_thumbprint": self.confirmation_thumbprint,
        }
