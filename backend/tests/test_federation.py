"""Public federation surface: OIDC discovery, public JWKS, SPIFFE bundle.

These endpoints are what makes ClaySeal-issued JWT-SVIDs verifiable by
external systems (Bedrock AgentCore CustomJWTAuthorizer, Keycloak, generic
RFC 7523 consumers, SPIFFE https_web federation) with NO ClaySeal code.
"""

from __future__ import annotations

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa

from clayseal.identity import verify_offline
from clayseal.identity.errors import InvalidTokenError

from .attest import register_and_identify


def test_openid_configuration_is_public_and_points_at_jwks(client, customer):
    cid = customer["customer_id"]
    resp = client.get(f"/t/{cid}/.well-known/openid-configuration")
    assert resp.status_code == 200
    doc = resp.json()
    assert doc["issuer"]
    assert doc["jwks_uri"].endswith(f"/t/{cid}/jwks.json")
    assert doc["id_token_signing_alg_values_supported"] == ["RS256"]


def test_agent_identity_configuration_is_public(client, customer):
    cid = customer["customer_id"]
    resp = client.get(f"/t/{cid}/.well-known/agent-identity.json")
    assert resp.status_code == 200
    doc = resp.json()
    assert doc["profile"] == "clayseal-agent-identity-v1"
    assert doc["jwks_uri"].endswith(f"/t/{cid}/jwks.json")
    assert doc["proof_of_possession_required"] is True
    assert "JWT" in doc["supported_token_types"]


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
    public discovery documents, verifies an ClaySeal JWT-SVID."""
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


def test_offline_verifier_accepts_public_jwks(client, customer):
    cid = customer["customer_id"]
    token = register_and_identify(client, customer["headers"]).json()["token"]
    jwks = client.get(f"/t/{cid}/jwks.json").json()
    issuer = client.get(f"/t/{cid}/.well-known/openid-configuration").json()["issuer"]

    claims = verify_offline(token, jwks=jwks, issuer=issuer, audience=cid)

    assert claims["aud"] == cid
    assert claims["sub"].startswith("spiffe://")
    assert claims["cnf"]["jkt"]


def test_offline_verifier_rejects_wrong_audience(client, customer):
    cid = customer["customer_id"]
    token = register_and_identify(client, customer["headers"]).json()["token"]
    jwks = client.get(f"/t/{cid}/jwks.json").json()
    issuer = client.get(f"/t/{cid}/.well-known/openid-configuration").json()["issuer"]

    try:
        verify_offline(token, jwks=jwks, issuer=issuer, audience="other-service")
    except InvalidTokenError as exc:
        assert exc.code == "invalid_token"
        assert "audience" in exc.message.lower()
    else:  # pragma: no cover - explicit failure path is clearer in assertion output
        raise AssertionError("wrong audience was accepted")


def test_offline_verifier_rejects_stale_jwks(client, customer):
    cid = customer["customer_id"]
    token = register_and_identify(client, customer["headers"]).json()["token"]
    issuer = client.get(f"/t/{cid}/.well-known/openid-configuration").json()["issuer"]

    try:
        verify_offline(token, jwks={"keys": []}, issuer=issuer, audience=cid)
    except InvalidTokenError as exc:
        assert exc.details["kid"]
    else:  # pragma: no cover
        raise AssertionError("empty JWKS was accepted")


def test_default_token_typ_is_spiffe_jwt(client, customer):
    """The default credential is a conformant SPIFFE JWT-SVID: typ == "JWT"."""
    token = register_and_identify(client, customer["headers"]).json()["token"]
    assert pyjwt.get_unverified_header(token)["typ"] == "JWT"


def test_wit_typ_opt_in_mints_wit_shaped_token(client, customer):
    """WIMSE WIT framing: typ=wit+jwt with cnf REQUIRED (sender-constrained)."""
    resp = register_and_identify(client, customer["headers"], token_typ="wit+jwt")
    assert resp.status_code == 200
    token = resp.json()["token"]
    header = pyjwt.get_unverified_header(token)
    assert header["typ"] == "wit+jwt"
    claims = pyjwt.decode(token, options={"verify_signature": False})
    assert claims["cnf"]["jkt"]  # never a bearer token
    assert claims["sub"].startswith("spiffe://")


def test_unknown_token_typ_rejected(client, customer):
    resp = register_and_identify(client, customer["headers"], token_typ="bearer+jwt")
    assert resp.status_code == 422  # rejected at the schema boundary
