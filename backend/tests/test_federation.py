"""Public federation surface: OIDC discovery, public JWKS, SPIFFE bundle.

These endpoints are what makes AgentAuth-issued JWT-SVIDs verifiable by
external systems (Bedrock AgentCore CustomJWTAuthorizer, Keycloak, generic
RFC 7523 consumers, SPIFFE https_web federation) with NO AgentAuth code.
"""

from __future__ import annotations

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa

from .attest import register_and_identify


def test_openid_configuration_is_public_and_points_at_jwks(client, customer):
    cid = customer["customer_id"]
    resp = client.get(f"/t/{cid}/.well-known/openid-configuration")
    assert resp.status_code == 200
    doc = resp.json()
    assert doc["issuer"]
    assert doc["jwks_uri"].endswith(f"/t/{cid}/jwks.json")
    assert doc["id_token_signing_alg_values_supported"] == ["RS256"]


def test_public_jwks_requires_no_api_key(client, customer):
    cid = customer["customer_id"]
    register_and_identify(client, customer["headers"])  # forces key creation
    resp = client.get(f"/t/{cid}/jwks.json")
    assert resp.status_code == 200
    keys = resp.json()["keys"]
    assert keys and all(k["kty"] == "RSA" and k["alg"] == "RS256" for k in keys)


def test_unknown_tenant_is_404(client):
    assert client.get("/t/nope/.well-known/openid-configuration").status_code == 404
    assert client.get("/t/nope/jwks.json").status_code == 404
    assert client.get("/t/nope/spiffe-bundle.json").status_code == 404


def test_spiffe_bundle_shape(client, customer):
    cid = customer["customer_id"]
    register_and_identify(client, customer["headers"])
    resp = client.get(f"/t/{cid}/spiffe-bundle.json")
    assert resp.status_code == 200
    bundle = resp.json()
    assert bundle["spiffe_refresh_hint"] > 0
    assert bundle["spiffe_sequence"] > 0
    assert bundle["keys"] and all(k["use"] == "jwt-svid" for k in bundle["keys"])


def test_issued_token_verifies_with_stock_pyjwt_via_public_jwks(client, customer):
    """The end-to-end federation claim: an off-the-shelf validator, fed only the
    public discovery documents, verifies an AgentAuth JWT-SVID."""
    cid = customer["customer_id"]
    token = register_and_identify(client, customer["headers"]).json()["token"]

    jwks = client.get(f"/t/{cid}/jwks.json").json()
    header = pyjwt.get_unverified_header(token)
    match = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    public_key = pyjwt.algorithms.RSAAlgorithm.from_jwk(match)
    assert isinstance(public_key, rsa.RSAPublicKey)

    issuer = client.get(f"/t/{cid}/.well-known/openid-configuration").json()["issuer"]
    claims = pyjwt.decode(
        token,
        key=public_key,
        algorithms=["RS256"],
        issuer=issuer,
        options={"verify_aud": False},
    )
    assert claims["sub"].startswith("spiffe://")
    assert "cnf" in claims  # sender-constrained: the PoP thumbprint travels
