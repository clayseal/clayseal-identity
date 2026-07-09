"""Agent identity profile helpers.

These functions are intentionally small and dependency-light. They make Clay
Seal useful as a standalone OSS identity toolkit: explain a token, lint it for
agent-identity hygiene, and normalize verified claims into a predictable shape.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import jwt

PROFILE_NAME = "clayseal-agent-identity-v1"
RECOMMENDED_TTL_SECONDS = 15 * 60
MAX_RECOMMENDED_TTL_SECONDS = 60 * 60
SUPPORTED_TOKEN_TYPES = {"clayseal-svid+jwt", "wit+jwt"}
SUPPORTED_ALGORITHMS = {"RS256"}
REQUIRED_CLAIMS = {"iss", "sub", "aud", "exp", "iat", "jti"}
RECOMMENDED_AGENT_CLAIMS = {"agent_id", "agent_type", "owner"}


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
    def from_claims(cls, claims: dict[str, Any]) -> "AgentIdentityClaims":
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


@dataclass
class LintFinding:
    level: str
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"level": self.level, "code": self.code, "message": self.message}


def decode_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return ``(header, claims)`` without verifying the signature."""
    header = jwt.get_unverified_header(token)
    claims = jwt.decode(token, options={"verify_signature": False})
    return header, claims


def explain_token(token: str) -> dict[str, Any]:
    """Decode and summarize an agent identity token without verification."""
    header, claims = decode_unverified(token)
    normalized = AgentIdentityClaims.from_claims(claims)
    ttl = None
    if isinstance(claims.get("exp"), int) and isinstance(claims.get("iat"), int):
        ttl = claims["exp"] - claims["iat"]
    return {
        "profile": PROFILE_NAME,
        "header": header,
        "identity": normalized.to_dict(),
        "ttl_seconds": ttl,
        "claims": claims,
    }


def lint_token(token: str) -> list[LintFinding]:
    """Lint a token for Clay Seal's agent identity profile."""
    findings: list[LintFinding] = []
    try:
        header, claims = decode_unverified(token)
    except jwt.InvalidTokenError as exc:
        return [
            LintFinding(
                "fail",
                "token.parse",
                f"Token is not a parseable JWT: {exc}",
            )
        ]

    alg = header.get("alg")
    typ = header.get("typ")
    if alg in SUPPORTED_ALGORITHMS:
        findings.append(LintFinding("pass", "header.alg", f"algorithm is {alg}"))
    else:
        findings.append(
            LintFinding("fail", "header.alg", f"expected RS256, found {alg!r}")
        )
    if typ in SUPPORTED_TOKEN_TYPES:
        findings.append(LintFinding("pass", "header.typ", f"token type is {typ}"))
    else:
        findings.append(
            LintFinding(
                "fail",
                "header.typ",
                f"expected one of {sorted(SUPPORTED_TOKEN_TYPES)}, found {typ!r}",
            )
        )
    if header.get("kid"):
        findings.append(LintFinding("pass", "header.kid", "key id is present"))
    else:
        findings.append(LintFinding("fail", "header.kid", "key id is missing"))

    for claim in sorted(REQUIRED_CLAIMS):
        if claims.get(claim) is not None:
            findings.append(LintFinding("pass", f"claim.{claim}", f"{claim} is present"))
        else:
            findings.append(LintFinding("fail", f"claim.{claim}", f"{claim} is missing"))

    for claim in sorted(RECOMMENDED_AGENT_CLAIMS):
        if claims.get(claim):
            findings.append(LintFinding("pass", f"claim.{claim}", f"{claim} is present"))
        else:
            findings.append(
                LintFinding(
                    "warn",
                    f"claim.{claim}",
                    f"{claim} is recommended for agent-aware logs and debugging",
                )
            )

    cnf = claims.get("cnf") or {}
    if cnf.get("jkt"):
        findings.append(
            LintFinding("pass", "claim.cnf.jkt", "sender-constraining key thumbprint is present")
        )
    else:
        findings.append(
            LintFinding("fail", "claim.cnf.jkt", "sender-constraining cnf.jkt is missing")
        )

    ttl = None
    if isinstance(claims.get("exp"), int) and isinstance(claims.get("iat"), int):
        ttl = claims["exp"] - claims["iat"]
        if ttl <= RECOMMENDED_TTL_SECONDS:
            findings.append(LintFinding("pass", "ttl.short", f"TTL is {ttl}s"))
        elif ttl <= MAX_RECOMMENDED_TTL_SECONDS:
            findings.append(
                LintFinding("warn", "ttl.medium", f"TTL is {ttl}s; prefer <=900s for agents")
            )
        else:
            findings.append(
                LintFinding("fail", "ttl.long", f"TTL is {ttl}s; agent tokens should be short-lived")
            )
    else:
        findings.append(
            LintFinding("warn", "ttl.unknown", "could not compute TTL from exp and iat")
        )

    sub = str(claims.get("sub") or "")
    if sub.startswith("spiffe://"):
        findings.append(LintFinding("pass", "subject.spiffe", "subject is SPIFFE-shaped"))
    else:
        findings.append(
            LintFinding("warn", "subject.spiffe", "subject is not SPIFFE-shaped")
        )
    return findings


def lint_summary(findings: list[LintFinding]) -> dict[str, int]:
    counts = {"pass": 0, "warn": 0, "fail": 0}
    for finding in findings:
        if finding.level in counts:
            counts[finding.level] += 1
    return counts
