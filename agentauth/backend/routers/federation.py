"""Public federation endpoints: let ANYONE verify our credentials with standard tooling.

Per-tenant, unauthenticated, read-only public-key documents:

- ``GET /t/{customer_id}/.well-known/openid-configuration`` — OIDC-style
  discovery. Point any JWKS-based validator at it (AWS Bedrock AgentCore's
  CustomJWTAuthorizer takes exactly this URL; Keycloak, generic OAuth resource
  servers, and RFC 7523 consumers resolve ``jwks_uri`` from it).
- ``GET /t/{customer_id}/jwks.json`` — the tenant's RS256 public keys (RFC 7517).
- ``GET /t/{customer_id}/spiffe-bundle.json`` — the same keys in SPIFFE bundle
  format (``use: "jwt-svid"`` + ``spiffe_sequence``/``spiffe_refresh_hint``),
  so SPIFFE-federation-aware peers can trust this tenant via the ``https_web``
  profile.

Only public material is served; tenant enumeration yields nothing beyond what a
presented token already reveals (its issuer and key ids).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import identity as identity_service
from ..config import get_settings
from ..deps import get_db
from ..models import Customer, SigningKey, to_epoch

router = APIRouter(tags=["federation"])

SPIFFE_REFRESH_HINT_SECONDS = 300


def _require_customer(db: Session, customer_id: str) -> Customer:
    customer = db.get(Customer, customer_id)
    if customer is None:
        raise HTTPException(status_code=404, detail="unknown tenant")
    return customer


@router.get("/t/{customer_id}/.well-known/openid-configuration")
def openid_configuration(
    customer_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    _require_customer(db, customer_id)
    settings = get_settings()
    base = str(request.base_url).rstrip("/")
    return {
        "issuer": settings.jwt_issuer,
        "jwks_uri": f"{base}/t/{customer_id}/jwks.json",
        "id_token_signing_alg_values_supported": [identity_service.JWT_ALGORITHM],
        "token_endpoint_auth_signing_alg_values_supported": [identity_service.JWT_ALGORITHM],
        "subject_types_supported": ["public"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "agent_id", "cnf"],
    }


@router.get("/t/{customer_id}/jwks.json")
def public_jwks(customer_id: str, db: Session = Depends(get_db)) -> dict:
    _require_customer(db, customer_id)
    return identity_service.build_jwks(db, customer_id)


@router.get("/t/{customer_id}/spiffe-bundle.json")
def spiffe_bundle(customer_id: str, db: Session = Depends(get_db)) -> dict:
    """SPIFFE bundle (https_web profile): JWKS + jwt-svid use + sequencing."""
    _require_customer(db, customer_id)
    jwks = identity_service.build_jwks(db, customer_id)
    for key in jwks["keys"]:
        key["use"] = "jwt-svid"
    latest = db.scalar(
        select(SigningKey)
        .where(SigningKey.customer_id == customer_id)
        .order_by(SigningKey.created_at.desc())
    )
    sequence = to_epoch(latest.created_at) if latest is not None else 0
    return {
        "keys": jwks["keys"],
        "spiffe_sequence": sequence,
        "spiffe_refresh_hint": SPIFFE_REFRESH_HINT_SECONDS,
    }
