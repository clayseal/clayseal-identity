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
    assert jwt.get_unverified_header(token)["typ"] == "clayseal-svid+jwt"
    validated = client.post(
        "/v1/validate",
        json={"token": token, "pop": _validate_pop(client, customer["headers"], token)},
        headers=customer["headers"],
    )
    assert validated.status_code == 200, validated.text
    assert validated.json()["valid"] is True
