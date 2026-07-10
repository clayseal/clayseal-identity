"""Real cloud / Kubernetes node attestation.

Each attestor is exercised against genuinely-signed evidence (our own keys stand
in for Google / AWS / the cluster), proving the verification is real crypto —
signatures, audiences, issuers, and expiry are all enforced, and forged or
substituted evidence is rejected.
"""
from __future__ import annotations

import base64
import datetime
import json
import time

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.x509.oid import NameOID

from clayseal.backend.errors import AttestationDeniedError
from clayseal.backend.node_attestors import (
    AwsIidAttestor,
    GcpIitAttestor,
    K8sPsatAttestor,
    expected_audience,
)
from clayseal.workload_keys import canonical_public_pem, keyhash_for_pem

TENANT = "tenant-123"
MAX_TTL = 900


# --- helpers ---------------------------------------------------------------- #
def _rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(public_key, kid: str) -> dict:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk


def _workload_key_pem() -> str:
    key = ed25519.Ed25519PrivateKey.generate()
    return canonical_public_pem(
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def _aud_for(workload_pem: str) -> str:
    return expected_audience(TENANT, keyhash_for_pem(workload_pem))


# --- GCP instance identity token -------------------------------------------- #
@pytest.fixture
def gcp_signer():
    key = _rsa()
    jwks = {"keys": [_jwk(key.public_key(), "gcp-kid-1")]}
    attestor = GcpIitAttestor(jwks_fetch=lambda _url: jwks)
    return key, attestor


def _gcp_token(key, *, aud, iss="https://accounts.google.com", ttl=600, ce=None):
    now = int(time.time())
    claims = {
        "iss": iss,
        "aud": aud,
        "sub": "112233445566",
        "azp": "112233445566",
        "iat": now,
        "exp": now + ttl,
        "google": {
            "compute_engine": ce
            or {
                "project_id": "risk-prod",
                "project_number": 42,
                "zone": "us-central1-a",
                "instance_id": "8087716956341",
                "instance_name": "agent-runner-1",
            }
        },
    }
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "gcp-kid-1"})


def test_gcp_verifies_and_derives_selectors(gcp_signer):
    key, attestor = gcp_signer
    wl = _workload_key_pem()
    token = _gcp_token(key, aud=_aud_for(wl))
    result = attestor.verify({"token": token}, audience=_aud_for(wl), max_ttl_seconds=MAX_TTL)
    assert set(result.node_selectors) == {
        "gcp_iit:project-id:risk-prod",
        "gcp_iit:instance-id:8087716956341",
        "gcp_iit:zone:us-central1-a",
        "gcp_iit:instance-name:agent-runner-1",
    }
    assert result.node_id == "8087716956341"


def test_gcp_rejects_key_substitution_via_audience(gcp_signer):
    """A token minted for one workload key can't bind another: the audience
    encodes the key thumbprint."""
    key, attestor = gcp_signer
    wl_a = _workload_key_pem()
    wl_b = _workload_key_pem()
    token = _gcp_token(key, aud=_aud_for(wl_a))  # minted for A
    with pytest.raises(AttestationDeniedError, match="audience"):
        attestor.verify({"token": token}, audience=_aud_for(wl_b), max_ttl_seconds=MAX_TTL)


def test_gcp_rejects_wrong_issuer(gcp_signer):
    key, attestor = gcp_signer
    wl = _workload_key_pem()
    token = _gcp_token(key, aud=_aud_for(wl), iss="https://accounts.evil.example")
    with pytest.raises(AttestationDeniedError):
        attestor.verify({"token": token}, audience=_aud_for(wl), max_ttl_seconds=MAX_TTL)


def test_gcp_rejects_foreign_signing_key(gcp_signer):
    _key, attestor = gcp_signer
    attacker = _rsa()
    wl = _workload_key_pem()
    token = _gcp_token(attacker, aud=_aud_for(wl))  # signed by a key not in JWKS
    with pytest.raises(AttestationDeniedError):
        attestor.verify({"token": token}, audience=_aud_for(wl), max_ttl_seconds=MAX_TTL)


def test_gcp_rejects_expired(gcp_signer):
    key, attestor = gcp_signer
    wl = _workload_key_pem()
    now = int(time.time())
    claims = {
        "iss": "https://accounts.google.com",
        "aud": _aud_for(wl),
        "sub": "1",
        "iat": now - 1200,
        "exp": now - 600,
        "google": {"compute_engine": {"project_id": "p", "instance_id": "i"}},
    }
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "gcp-kid-1"})
    with pytest.raises(AttestationDeniedError, match="expired"):
        attestor.verify({"token": token}, audience=_aud_for(wl), max_ttl_seconds=MAX_TTL)


def test_gcp_rejects_overlong_ttl(gcp_signer):
    key, attestor = gcp_signer
    wl = _workload_key_pem()
    token = _gcp_token(key, aud=_aud_for(wl), ttl=100_000)
    with pytest.raises(AttestationDeniedError, match="too long"):
        attestor.verify({"token": token}, audience=_aud_for(wl), max_ttl_seconds=MAX_TTL)


# --- Kubernetes PSAT (TokenReview) ------------------------------------------ #
class _FakeReviewer:
    def __init__(self, response: dict, *, expect_audience: str | None = None):
        self._response = response
        self._expect_audience = expect_audience
        self.calls: list[tuple[str, list[str]]] = []

    def review(self, token: str, audiences: list[str]) -> dict:
        self.calls.append((token, audiences))
        if self._expect_audience and self._expect_audience not in audiences:
            return {"status": {"authenticated": False}}
        return self._response


def _authenticated(ns="prod", sa="agent-runner", pod="agent-runner-xyz", uid="pod-uid-1"):
    return {
        "status": {
            "authenticated": True,
            "user": {
                "username": f"system:serviceaccount:{ns}:{sa}",
                "extra": {
                    "authentication.kubernetes.io/pod-name": [pod],
                    "authentication.kubernetes.io/pod-uid": [uid],
                },
            },
        }
    }


def test_k8s_psat_verifies_and_derives_selectors():
    wl = _workload_key_pem()
    reviewer = _FakeReviewer(_authenticated(), expect_audience=_aud_for(wl))
    attestor = K8sPsatAttestor(reviewer=reviewer, cluster="prod-cluster")
    result = attestor.verify(
        {"token": "projected-sa-token"}, audience=_aud_for(wl), max_ttl_seconds=MAX_TTL
    )
    assert set(result.node_selectors) == {
        "k8s_psat:cluster:prod-cluster",
        "k8s_psat:agent_ns:prod",
        "k8s_psat:agent_sa:agent-runner",
        "k8s_psat:pod-name:agent-runner-xyz",
    }
    # The audience we bound the workload key to is what TokenReview was asked to check.
    assert reviewer.calls[0][1] == [_aud_for(wl)]


def test_k8s_psat_rejects_unauthenticated():
    wl = _workload_key_pem()
    attestor = K8sPsatAttestor(
        reviewer=_FakeReviewer({"status": {"authenticated": False}}), cluster="c"
    )
    with pytest.raises(AttestationDeniedError, match="not authenticated"):
        attestor.verify({"token": "t"}, audience=_aud_for(wl), max_ttl_seconds=MAX_TTL)


def test_k8s_psat_rejects_non_service_account():
    wl = _workload_key_pem()
    resp = {"status": {"authenticated": True, "user": {"username": "kube-admin"}}}
    attestor = K8sPsatAttestor(reviewer=_FakeReviewer(resp), cluster="c")
    with pytest.raises(AttestationDeniedError, match="service account"):
        attestor.verify({"token": "t"}, audience=_aud_for(wl), max_ttl_seconds=MAX_TTL)


# --- AWS instance identity document ----------------------------------------- #
def _aws_cert_and_key():
    key = _rsa()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aws-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


def _sign_doc(key, document: str) -> str:
    sig = key.sign(document.encode(), padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(sig).decode()


def test_aws_iid_verifies_and_derives_selectors():
    key, cert = _aws_cert_and_key()
    attestor = AwsIidAttestor(region_certs={"us-east-1": cert})
    doc = json.dumps(
        {
            "accountId": "123456789012",
            "region": "us-east-1",
            "instanceId": "i-0abc123",
            "imageId": "ami-999",
            "pendingTime": "2026-07-10T00:00:00Z",
        }
    )
    result = attestor.verify(
        {"document": doc, "signature": _sign_doc(key, doc)},
        audience="unused-for-aws",
        max_ttl_seconds=MAX_TTL,
    )
    assert set(result.node_selectors) == {
        "aws_iid:account:123456789012",
        "aws_iid:region:us-east-1",
        "aws_iid:instance-id:i-0abc123",
        "aws_iid:image-id:ami-999",
    }
    assert result.node_id == "i-0abc123"


def test_aws_iid_rejects_tampered_document():
    key, cert = _aws_cert_and_key()
    attestor = AwsIidAttestor(region_certs={"us-east-1": cert})
    doc = json.dumps({"accountId": "1", "region": "us-east-1", "instanceId": "i-real"})
    signature = _sign_doc(key, doc)
    forged = json.dumps({"accountId": "1", "region": "us-east-1", "instanceId": "i-attacker"})
    with pytest.raises(AttestationDeniedError, match="signature does not match"):
        attestor.verify(
            {"document": forged, "signature": signature},
            audience="x",
            max_ttl_seconds=MAX_TTL,
        )


def test_aws_iid_rejects_unknown_region():
    key, cert = _aws_cert_and_key()
    attestor = AwsIidAttestor(region_certs={"us-east-1": cert})
    doc = json.dumps({"accountId": "1", "region": "eu-west-9", "instanceId": "i"})
    with pytest.raises(AttestationDeniedError, match="No AWS public certificate"):
        attestor.verify(
            {"document": doc, "signature": _sign_doc(key, doc)},
            audience="x",
            max_ttl_seconds=MAX_TTL,
        )
