"""Negative tests: ``verify_offline`` must reject JWT algorithm-confusion and
signature-tampering attacks. These are the classic JWT failure modes a
security-critical identity SDK must prove it rejects.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from clayseal.identity import verify_offline
from clayseal.identity.errors import InvalidTokenError

ISSUER = "clayseal.io"
AUD = "tools-api"
KID = "kid-1"


def _rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _public_pem(key) -> str:
    return (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )


def _jwks(public_key, kid: str = KID) -> dict:
    jwk = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


def _claims() -> dict:
    now = int(time.time())
    return {
        "iss": ISSUER,
        "sub": "spiffe://clayseal.io/customer/acme/agent/researcher",
        "aud": AUD,
        "iat": now,
        "exp": now + 600,
        "jti": "attack-test",
        "agent_id": "agent-1",
        "agent_type": "researcher",
        "owner": "alice@example.com",
        "cnf": {"jkt": "thumb"},
    }


def _headers(**overrides) -> dict:
    header = {"kid": KID, "typ": "JWT"}
    header.update(overrides)
    return header


def _seg(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


@pytest.fixture
def signer():
    key = _rsa_key()
    return key, _jwks(key.public_key())


def test_valid_token_verifies(signer):
    """Sanity: a correctly signed token passes, so the negative cases are meaningful."""
    key, jwks = signer
    token = pyjwt.encode(_claims(), key, algorithm="RS256", headers=_headers())
    claims = verify_offline(token, jwks=jwks, issuer=ISSUER, audience=AUD)
    assert claims["cnf"]["jkt"] == "thumb"


def test_rejects_alg_none(signer):
    _key, jwks = signer
    forged = f"{_seg(_headers(alg='none'))}.{_seg(_claims())}."
    with pytest.raises(InvalidTokenError) as exc:
        verify_offline(forged, jwks=jwks, issuer=ISSUER, audience=AUD)
    assert "algorithm" in exc.value.message.lower()


def test_rejects_hs256_confusion(signer):
    """RS256->HS256 confusion: forge an HS256 token using the RSA public key as
    the HMAC secret (hand-crafted, since PyJWT refuses to encode this). The
    RS256-only allowlist must reject it before any signature check."""
    key, jwks = signer
    pub = _public_pem(key).encode()
    signing_input = f"{_seg(_headers(alg='HS256'))}.{_seg(_claims())}"
    sig = hmac.new(pub, signing_input.encode(), hashlib.sha256).digest()
    forged = f"{signing_input}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
    with pytest.raises(InvalidTokenError) as exc:
        verify_offline(forged, jwks=jwks, issuer=ISSUER, audience=AUD)
    assert "algorithm" in exc.value.message.lower()


def test_rejects_unknown_kid(signer):
    key, jwks = signer
    token = pyjwt.encode(_claims(), key, algorithm="RS256", headers=_headers(kid="attacker-kid"))
    with pytest.raises(InvalidTokenError):
        verify_offline(token, jwks=jwks, issuer=ISSUER, audience=AUD)


def test_rejects_duplicate_kid_in_jwks(signer):
    key, jwks = signer
    attacker = _rsa_key()
    duplicate = _jwks(attacker.public_key())["keys"][0]
    jwks["keys"].append(duplicate)
    token = pyjwt.encode(_claims(), key, algorithm="RS256", headers=_headers())
    with pytest.raises(InvalidTokenError) as exc:
        verify_offline(token, jwks=jwks, issuer=ISSUER, audience=AUD)
    assert "multiple keys" in exc.value.message


def test_rejects_key_swap(signer):
    """A token signed by a different key but claiming a trusted kid must fail
    signature verification against the trusted JWKS."""
    _key, jwks = signer
    attacker = _rsa_key()
    token = pyjwt.encode(_claims(), attacker, algorithm="RS256", headers=_headers())
    with pytest.raises(InvalidTokenError):
        verify_offline(token, jwks=jwks, issuer=ISSUER, audience=AUD)


def test_rejects_stripped_signature(signer):
    key, jwks = signer
    token = pyjwt.encode(_claims(), key, algorithm="RS256", headers=_headers())
    stripped = token.rsplit(".", 1)[0] + "."
    with pytest.raises(InvalidTokenError):
        verify_offline(stripped, jwks=jwks, issuer=ISSUER, audience=AUD)


def test_rejects_tampered_signature(signer):
    key, jwks = signer
    token = pyjwt.encode(_claims(), key, algorithm="RS256", headers=_headers())
    head, sig = token.rsplit(".", 1)
    flipped = ("B" if sig[0] == "A" else "A") + sig[1:]
    with pytest.raises(InvalidTokenError):
        verify_offline(f"{head}.{flipped}", jwks=jwks, issuer=ISSUER, audience=AUD)
