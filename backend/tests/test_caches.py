"""Hot-path caches: TTLCache, verified-API-key cache (skips PBKDF2), decrypted
signing-material cache, and the process-wide KMS client cache."""
from __future__ import annotations

import sys
import time
import types

from clayseal.backend import deps, secret_encryption
from clayseal.backend import signing_keys as sk
from clayseal.backend.cache import TTLCache

PRIVATE_BEGIN = "-----BEGIN " + "PRIVATE " + "KEY-----"
PRIVATE_END = "-----END " + "PRIVATE " + "KEY-----"


# --- TTLCache -------------------------------------------------------------- #
def test_ttl_cache_hit_and_expiry():
    cache: TTLCache[str, int] = TTLCache(max_size=8, ttl_seconds=10)
    cache.set("a", 1)
    assert cache.get("a") == 1
    cache.invalidate("a")
    assert cache.get("a") is None


def test_ttl_cache_expires():
    cache: TTLCache[str, int] = TTLCache(max_size=8, ttl_seconds=0.05)
    cache.set("a", 1)
    time.sleep(0.08)
    assert cache.get("a") is None


def test_ttl_cache_evicts_oldest_when_full():
    cache: TTLCache[str, int] = TTLCache(max_size=2, ttl_seconds=100)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.set("c", 3)  # evicts "a"
    assert cache.get("a") is None
    assert cache.get("b") == 2
    assert cache.get("c") == 3


def test_ttl_cache_zero_ttl_is_noop():
    cache: TTLCache[str, int] = TTLCache(max_size=8, ttl_seconds=0)
    cache.set("a", 1)
    assert cache.get("a") is None


# --- Verified API-key cache (Task 7) --------------------------------------- #
def test_repeat_auth_skips_pbkdf2(client, customer, monkeypatch):
    deps.clear_api_key_cache()
    calls = {"n": 0}
    real = deps.verify_api_key

    def counting(api_key, encoded_hash):
        calls["n"] += 1
        return real(api_key, encoded_hash)

    monkeypatch.setattr(deps, "verify_api_key", counting)

    h = customer["headers"]
    assert client.get("/v1/agents", headers=h).status_code == 200
    after_first = calls["n"]
    assert after_first >= 1  # first call ran full PBKDF2 verification

    # Subsequent calls with the same key hit the cache; no more PBKDF2.
    for _ in range(3):
        assert client.get("/v1/agents", headers=h).status_code == 200
    assert calls["n"] == after_first


def test_cache_invalidated_when_stored_hash_changes(client, customer, monkeypatch):
    """A rotated/rehashed key must fall out of the fast path immediately."""
    deps.clear_api_key_cache()
    h = customer["headers"]
    assert client.get("/v1/agents", headers=h).status_code == 200  # populate cache

    # Simulate rotation: change the customer's stored hash out from under the cache.
    from clayseal.backend.db import SessionLocal
    from clayseal.backend.models import Customer

    with SessionLocal() as db:
        row = db.get(Customer, customer["customer_id"])
        row.api_key_hash = "pbkdf2_sha256$200000$" + "00" * 16 + "$" + "11" * 32
        db.add(row)
        db.commit()

    # The cached entry no longer matches the stored hash, so the (now-wrong)
    # cached customer must not authenticate the original key.
    assert client.get("/v1/agents", headers=h).status_code == 401


# --- Decrypted signing-material cache (Task 8) ----------------------------- #
def test_signing_key_decrypt_is_cached(monkeypatch):
    sk._signing_key_cache.clear()
    ciphertext = sk.encrypt_private_pem(f"{PRIVATE_BEGIN}\nZm9v\n{PRIVATE_END}")
    assert sk.is_encrypted_private_pem(ciphertext)

    calls = {"n": 0}
    real = sk.decrypt_secret

    def counting(stored, *, context):
        calls["n"] += 1
        return real(stored, context=context)

    monkeypatch.setattr(sk, "decrypt_secret", counting)

    first = sk.decrypt_private_pem(ciphertext)
    second = sk.decrypt_private_pem(ciphertext)
    assert first == second
    assert calls["n"] == 1  # second decrypt served from cache


# --- KMS client cache (Task 8) --------------------------------------------- #
def test_boto3_kms_client_is_cached(monkeypatch):
    made = {"n": 0}
    sentinel = object()
    fake_boto3 = types.ModuleType("boto3")

    def _client(service):
        made["n"] += 1
        assert service == "kms"
        return sentinel

    fake_boto3.client = _client
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    secret_encryption._cached_boto3_kms_client.cache_clear()

    c1 = secret_encryption._cached_boto3_kms_client()
    c2 = secret_encryption._cached_boto3_kms_client()
    assert c1 is c2 is sentinel
    assert made["n"] == 1

    provider = secret_encryption.AwsKmsProvider("arn:aws:kms:us-east-1:1:key/abc")
    assert provider._client() is sentinel
    assert made["n"] == 1  # provider reuses the cached client

    secret_encryption._cached_boto3_kms_client.cache_clear()
