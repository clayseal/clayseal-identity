"""WIMSE-framed tokens (High 9): a token minted with typ=wit+jwt must validate.

Previously /v1/validate rejected any typ != "clayseal-svid+jwt", so a wit+jwt
credential could be issued but never verified through the service.
"""
from __future__ import annotations

import time
import uuid

import jwt

from clayseal.backend import capabilities as cap_service
from tests.attest import WORKLOAD_PRIVATE_PEM, WORKLOAD_PUBLIC_PEM, register_and_identify


def _validate_pop(client, headers, token):
    challenge = client.post("/v1/challenge", headers=headers).json()["challenge"]
    keyhash = cap_service.keyhash_for_pem(WORKLOAD_PUBLIC_PEM)
    iat = int(time.time())
    jti = uuid.uuid4().hex
    return {
        "challenge": challenge,
        "signature": cap_service.sign_request_pop(
            WORKLOAD_PRIVATE_PEM,
            keyhash,
            challenge,
            htm="POST",
            htu="/v1/validate",
            ath=cap_service.token_hash(token),
            iat=iat,
            jti=jti,
            operation=("jwt", "validate"),
        ),
        "pubkey_pem": WORKLOAD_PUBLIC_PEM,
        "htm": "POST",
        "htu": "/v1/validate",
        "ath": cap_service.token_hash(token),
        "iat": iat,
        "jti": jti,
    }


def test_wit_jwt_token_is_issued_with_wit_typ(client, customer):
    resp = register_and_identify(
        client, customer["headers"], agent_type="wit-agent",
        scopes=["db:read"], token_typ="wit+jwt",
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["token"]
    assert jwt.get_unverified_header(token)["typ"] == "wit+jwt"


def test_wit_jwt_token_validates(client, customer):
    resp = register_and_identify(
        client, customer["headers"], agent_type="wit-agent-2",
        scopes=["db:read"], token_typ="wit+jwt",
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["token"]

    validated = client.post(
        "/v1/validate",
        json={"token": token, "pop": _validate_pop(client, customer["headers"], token)},
        headers=customer["headers"],
    )
    assert validated.status_code == 200, validated.text
    assert validated.json()["valid"] is True


def test_default_svid_typ_still_validates(client, customer):
    resp = register_and_identify(
        client, customer["headers"], agent_type="svid-agent", scopes=["db:read"],
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["token"]
    assert jwt.get_unverified_header(token)["typ"] == "JWT"
    validated = client.post(
        "/v1/validate",
        json={"token": token, "pop": _validate_pop(client, customer["headers"], token)},
        headers=customer["headers"],
    )
    assert validated.status_code == 200, validated.text
    assert validated.json()["valid"] is True


def test_default_token_is_spiffe_jwt_svid_conformant(client, customer):
    """A strict SPIFFE JWT-SVID validator's checks: typ=JWT, sub is the SPIFFE
    ID, aud and exp present."""
    import jwt as pyjwt

    token = register_and_identify(
        client, customer["headers"], agent_type="conformant", scopes=["db:read"]
    ).json()["token"]
    assert pyjwt.get_unverified_header(token)["typ"] == "JWT"
    claims = pyjwt.decode(token, options={"verify_signature": False})
    assert claims["sub"].startswith("spiffe://")
    assert claims["aud"] and claims["exp"]


def test_legacy_clayseal_typ_still_validates(client, customer):
    """Pre-0.6 tokens (typ=clayseal-svid+jwt) still verify, so a rollout does not
    reject credentials minted before the SPIFFE-typ default."""
    from clayseal.identity.verifier import DEFAULT_ALLOWED_TOKEN_TYPES

    assert "clayseal-svid+jwt" in DEFAULT_ALLOWED_TOKEN_TYPES
    assert "JWT" in DEFAULT_ALLOWED_TOKEN_TYPES
