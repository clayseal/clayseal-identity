"""Tests for at-rest signing key encryption."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from clayseal.backend.db import SessionLocal
from clayseal.backend.identity import create_signing_key, get_active_key
from clayseal.backend.models import Customer, SigningKey
from clayseal.backend.signing_keys import (
    decrypt_private_pem,
    encrypt_private_pem,
    is_encrypted_private_pem,
    maybe_reencrypt_signing_key,
)

PRIVATE_BEGIN = "-----BEGIN " + "PRIVATE " + "KEY-----"
PRIVATE_END = "-----END " + "PRIVATE " + "KEY-----"
PUBLIC_BEGIN = "-----BEGIN " + "PUBLIC KEY-----"
PUBLIC_END = "-----END " + "PUBLIC KEY-----"


def _fake_private_pem(body: str) -> str:
    return f"{PRIVATE_BEGIN}\n{body}\n{PRIVATE_END}\n"


def _fake_public_pem(body: str) -> str:
    return f"{PUBLIC_BEGIN}\n{body}\n{PUBLIC_END}\n"


def test_create_signing_key_stores_encrypted_private_pem(customer):
    with SessionLocal() as db:
        key = create_signing_key(db, customer["customer_id"])
        assert is_encrypted_private_pem(key.private_pem)
        assert "BEGIN" not in key.private_pem
        pem = decrypt_private_pem(key.private_pem)
        assert "BEGIN PRIVATE KEY" in pem
        assert key.algorithm == "RS256"
        public_key = serialization.load_pem_public_key(key.public_pem.encode())
        assert isinstance(public_key, rsa.RSAPublicKey)


def test_maybe_reencrypt_signing_key_upgrades_legacy_plaintext(customer):
    with SessionLocal() as db:
        cust = db.get(Customer, customer["customer_id"])
        legacy = SigningKey(
            kid="legacy-kid",
            customer_id=cust.id,
            private_pem=_fake_private_pem("legacy"),
            public_pem=_fake_public_pem("legacy"),
            algorithm="RS256",
            status="active",
        )
        db.add(legacy)
        db.commit()
        db.refresh(legacy)
        maybe_reencrypt_signing_key(db, legacy)
        db.refresh(legacy)
        assert is_encrypted_private_pem(legacy.private_pem)
        assert decrypt_private_pem(legacy.private_pem).startswith(PRIVATE_BEGIN)


def test_get_active_key_replaces_legacy_eddsa_signing_key(customer):
    with SessionLocal() as db:
        cust = db.get(Customer, customer["customer_id"])
        current = get_active_key(db, cust.id)
        current.status = "retired"
        db.add(current)
        db.commit()
        legacy = SigningKey(
            kid="legacy-eddsa-kid",
            customer_id=cust.id,
            private_pem=_fake_private_pem("legacy"),
            public_pem=_fake_public_pem("legacy"),
            algorithm="EdDSA",
            status="active",
        )
        db.add(legacy)
        db.commit()

        key = get_active_key(db, cust.id)
        db.refresh(legacy)

        assert legacy.status == "retired"
        assert key.kid != legacy.kid
        assert key.algorithm == "RS256"


def test_encrypt_decrypt_roundtrip():
    pem = _fake_private_pem("abc")
    stored = encrypt_private_pem(pem)
    assert decrypt_private_pem(stored) == pem


def test_decrypt_private_pem_refuses_plaintext_when_encryption_enabled():
    pem = _fake_private_pem("abc")
    with pytest.raises(ValueError, match="refusing to load plaintext signing key"):
        decrypt_private_pem(pem)
