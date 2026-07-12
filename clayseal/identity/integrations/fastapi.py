"""FastAPI helpers for protecting tool/resource endpoints with agent identity."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from clayseal.identity.profile import AgentIdentityClaims
from clayseal.identity.verifier import verify_offline


class AgentIdentityVerifier:
    """Callable FastAPI dependency that verifies ``Authorization: Bearer``."""

    def __init__(
        self,
        *,
        jwks: Mapping[str, Any] | Iterable[Mapping[str, Any]],
        issuer: str,
        audience: str | Iterable[str],
        require_cnf: bool = True,
    ) -> None:
        self.jwks = jwks
        self.issuer = issuer
        self.audience = audience
        self.require_cnf = require_cnf

    def __call__(self, authorization: str = "") -> AgentIdentityClaims:
        try:
            from fastapi import HTTPException
        except ImportError as exc:  # pragma: no cover - fastapi is installed here
            raise RuntimeError("Install fastapi to use AgentIdentityVerifier") from exc

        # FastAPI dependency injection only applies Header defaults when they
        # appear in the function signature. This branch supports direct unit use.
        if not authorization:
            raise HTTPException(status_code=401, detail="missing Authorization header")
        if not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="expected Bearer token")
        token = authorization.split(" ", 1)[1].strip()
        try:
            claims = verify_offline(
                token,
                jwks=self.jwks,
                issuer=self.issuer,
                audience=self.audience,
                require_cnf=self.require_cnf,
            )
        except Exception as exc:  # noqa: BLE001 - map verifier errors to HTTP
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return AgentIdentityClaims.from_claims(claims)

    @classmethod
    def dependency(
        cls,
        *,
        jwks: Mapping[str, Any] | Iterable[Mapping[str, Any]],
        issuer: str,
        audience: str | Iterable[str],
        require_cnf: bool = True,
    ):
        from fastapi import Header

        verifier = cls(jwks=jwks, issuer=issuer, audience=audience, require_cnf=require_cnf)

        def _dep(authorization: str = Header(default="")) -> AgentIdentityClaims:
            return verifier(authorization)

        return _dep
