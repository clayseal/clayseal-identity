"""End-to-end: a real GCP instance identity token, verified against a (fake)
Google JWKS, drives the full issuance path — registration-entry match, credential
mint, and a workload-key-bound Biscuit — with no static trust anchor involved.
"""
from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from clayseal.backend.db import SessionLocal
from clayseal.backend.errors import AttestationDeniedError
from clayseal.backend.identity import attest
from clayseal.backend.models import Customer, RegistrationEntry, new_id
from clayseal.backend.node_attestors import (
    CLOUD_EVIDENCE_KIND,
    GcpIitAttestor,
    clear_cloud_attestors,
    expected_audience,
    register_cloud_attestor,
)
from clayseal.workload_keys import canonical_public_pem, keyhash_for_pem

PROJECT = "risk-prod"
INSTANCE = "8087716956341"


@pytest.fixture
def gcp_key():
    """Register a GCP attestor backed by a local fake JWKS; clean up after."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "gcp-1", "use": "sig", "alg": "RS256"})
    register_cloud_attestor(GcpIitAttestor(jwks_fetch=lambda _u: {"keys": [jwk]}))
    yield key
    clear_cloud_attestors()


def _workload_key() -> tuple[str, str]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = canonical_public_pem(
        priv.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return pub, keyhash_for_pem(pub)


def _bundle(key, *, tenant_id: str, workload_pem: str, keyhash: str) -> str:
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": "https://accounts.google.com",
            "aud": expected_audience(tenant_id, keyhash),
            "sub": "112233",
            "iat": now,
            "exp": now + 120,  # within the 300s default attestation max TTL
            "google": {
                "compute_engine": {
                    "project_id": PROJECT,
                    "zone": "us-central1-a",
                    "instance_id": INSTANCE,
                    "instance_name": "agent-1",
                }
            },
        },
        key,
        algorithm="RS256",
        headers={"kid": "gcp-1"},
    )
    return json.dumps(
        {
            "kind": CLOUD_EVIDENCE_KIND,
            "type": "gcp_iit",
            "evidence": {"token": token},
            "workload_pubkey_pem": workload_pem,
        }
    )


def _register_entry(db, customer_id: str) -> None:
    db.add(
        RegistrationEntry(
            id=new_id(),
            customer_id=customer_id,
            agent_type="researcher",
            selectors=[f"gcp_iit:project-id:{PROJECT}", f"gcp_iit:instance-id:{INSTANCE}"],
            capabilities=[{"resource": "db", "action": "read"}],
            scopes=["db:read"],
            owner="ops@customer.com",
            ttl_seconds=3600,
        )
    )


def test_gcp_evidence_issues_a_bound_credential(customer, gcp_key):
    workload_pem, keyhash = _workload_key()
    with SessionLocal() as db:
        cust = db.get(Customer, customer["customer_id"])
        _register_entry(db, cust.id)
        db.commit()

        bundle = _bundle(gcp_key, tenant_id=cust.id, workload_pem=workload_pem, keyhash=keyhash)
        agent, token = attest(db, cust, attestation_document=bundle)

        assert agent.agent_type == "researcher"
        claims = jwt.decode(token, options={"verify_signature": False})
        assert claims["agent_type"] == "researcher"
        # Credential is bound to the workload key we proved possession of.
        assert claims["cnf"]["jkt"] == keyhash


def test_same_gcp_token_cannot_mint_twice(customer, gcp_key):
    workload_pem, keyhash = _workload_key()
    with SessionLocal() as db:
        cust = db.get(Customer, customer["customer_id"])
        _register_entry(db, cust.id)
        db.commit()
        bundle = _bundle(gcp_key, tenant_id=cust.id, workload_pem=workload_pem, keyhash=keyhash)
        attest(db, cust, attestation_document=bundle)
        with pytest.raises(AttestationDeniedError, match="already been used"):
            attest(db, cust, attestation_document=bundle)


def test_gcp_token_for_other_tenant_is_rejected(customer, gcp_key):
    """A token whose audience binds a different tenant fails: the audience is
    tenant + key scoped."""
    workload_pem, keyhash = _workload_key()
    with SessionLocal() as db:
        cust = db.get(Customer, customer["customer_id"])
        _register_entry(db, cust.id)
        db.commit()
        # Audience minted for a different tenant id.
        bundle = _bundle(gcp_key, tenant_id="someone-else", workload_pem=workload_pem, keyhash=keyhash)
        with pytest.raises(AttestationDeniedError, match="audience"):
            attest(db, cust, attestation_document=bundle)


def test_unregistered_attestor_type_is_rejected(customer):
    clear_cloud_attestors()  # nothing enabled
    workload_pem, _ = _workload_key()
    with SessionLocal() as db:
        cust = db.get(Customer, customer["customer_id"])
        bundle = json.dumps(
            {
                "kind": CLOUD_EVIDENCE_KIND,
                "type": "gcp_iit",
                "evidence": {"token": "x"},
                "workload_pubkey_pem": workload_pem,
            }
        )
        with pytest.raises(AttestationDeniedError, match="not enabled"):
            attest(db, cust, attestation_document=bundle)
