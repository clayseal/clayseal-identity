"""Human-friendly, unverified inspection for Clay Seal identity tokens."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import jwt

from .errors import InvalidTokenError
from .profile import AgentIdentityClaims


def _utc_from_epoch(value: Any) -> datetime | None:
    if not isinstance(value, (int, float)):
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.isoformat().replace("+00:00", "Z")


def _audience_text(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if value is None:
        return ""
    return str(value)


@dataclass
class TokenInspection:
    """Readable view of a Clay Seal JWT.

    This is intentionally not a verifier. It decodes the JOSE header and claims
    without checking the signature so developers can understand what a token
    says. Use ``verify_offline`` or ``AgentSession.validate`` before trusting it.
    """

    header: dict[str, Any]
    claims: dict[str, Any]
    identity: AgentIdentityClaims
    expires_at: datetime | None
    issued_at: datetime | None
    inspected_at: datetime
    warnings: list[str] = field(default_factory=list)

    @property
    def token_type(self) -> str:
        return str(self.header.get("typ") or "")

    @property
    def algorithm(self) -> str:
        return str(self.header.get("alg") or "")

    @property
    def key_id(self) -> str:
        return str(self.header.get("kid") or "")

    @property
    def is_sender_constrained(self) -> bool:
        cnf = self.claims.get("cnf")
        return isinstance(cnf, dict) and bool(cnf.get("jkt"))

    @property
    def is_expired(self) -> bool:
        return self.expires_at is not None and self.expires_at <= self.inspected_at

    @property
    def expires_in_seconds(self) -> int | None:
        if self.expires_at is None:
            return None
        return int((self.expires_at - self.inspected_at).total_seconds())

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": False,
            "header": dict(self.header),
            "identity": self.identity.to_dict(),
            "token_type": self.token_type,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "sender_constrained": self.is_sender_constrained,
            "issued_at": _iso(self.issued_at),
            "expires_at": _iso(self.expires_at),
            "expires_in_seconds": self.expires_in_seconds,
            "expired": self.is_expired,
            "warnings": list(self.warnings),
        }

    def summary_lines(self) -> list[str]:
        identity = self.identity
        lines = [
            "Clay Seal token inspection (unverified)",
            f"  agent_id: {identity.agent_id or '(missing)'}",
            f"  agent_type: {identity.agent_type or '(missing)'}",
            f"  principal: {identity.principal or '(missing)'}",
            f"  subject: {identity.subject or '(missing)'}",
            f"  issuer: {identity.issuer or '(missing)'}",
            f"  audience: {_audience_text(identity.audience) or '(missing)'}",
            f"  token_type: {self.token_type or '(missing)'}",
            f"  algorithm: {self.algorithm or '(missing)'}",
            f"  key_id: {self.key_id or '(missing)'}",
            f"  sender_constrained: {'yes' if self.is_sender_constrained else 'no'}",
            f"  issued_at: {_iso(self.issued_at) or '(missing)'}",
            f"  expires_at: {_iso(self.expires_at) or '(missing)'}",
        ]
        if self.expires_in_seconds is not None:
            lines.append(f"  expires_in_seconds: {self.expires_in_seconds}")
        if identity.scopes:
            lines.append(f"  scopes: {', '.join(identity.scopes)}")
        if identity.selectors:
            lines.append(f"  selectors: {', '.join(identity.selectors)}")
        if self.warnings:
            lines.append("  warnings:")
            lines.extend(f"    - {warning}" for warning in self.warnings)
        return lines


def inspect_token(token: str, *, now: datetime | None = None) -> TokenInspection:
    """Decode a JWT-SVID for display without trusting it.

    The returned inspection is useful in examples, tests, and debug screens.
    It does not verify signature, issuer, audience, revocation, or
    proof-of-possession. Resource servers should use ``verify_offline`` or the
    hosted validation path for enforcement.
    """
    inspected_at = now or datetime.now(timezone.utc)
    try:
        header = jwt.get_unverified_header(token)
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.InvalidTokenError as exc:
        raise InvalidTokenError(
            "Token could not be decoded for inspection.",
            suggestion="Pass a complete Clay Seal JWT string.",
        ) from exc

    identity = AgentIdentityClaims.from_claims(claims)
    inspection = TokenInspection(
        header=dict(header),
        claims=dict(claims),
        identity=identity,
        expires_at=_utc_from_epoch(claims.get("exp")),
        issued_at=_utc_from_epoch(claims.get("iat")),
        inspected_at=inspected_at,
        warnings=["inspection is not verification"],
    )
    if not inspection.is_sender_constrained:
        inspection.warnings.append("missing cnf.jkt sender constraint")
    if inspection.expires_at is None:
        inspection.warnings.append("missing exp claim")
    elif inspection.is_expired:
        inspection.warnings.append("token is expired")
    if not inspection.algorithm:
        inspection.warnings.append("missing JOSE alg")
    if not inspection.key_id:
        inspection.warnings.append("missing JOSE kid")
    return inspection
