from __future__ import annotations

import json
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from clayseal.identity import verify_offline
from clayseal.identity.integrations.fastapi import AgentIdentityVerifier
from clayseal.identity.integrations.langchain import identity_config, with_agent_identity
from clayseal.identity.integrations.mcp import authorization_header, identity_metadata
from clayseal.identity.profile import AgentIdentityClaims


def _rsa_keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


def _token_and_jwks(claim_overrides=None):
    private, public = _rsa_keypair()
    now = int(time.time())
    claims = {
        "iss": "clayseal.io",
        "sub": "spiffe://clayseal.io/customer/acme/agent/researcher",
        "aud": "acme",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": "jti-1",
        "agent_id": "agent-1",
        "agent_type": "researcher",
        "owner": "alice@example.com",
        "scope": ["repo:read"],
        "selectors": ["k8s:sa:researcher"],
        "cnf": {"jkt": "thumbprint"},
    }
    if claim_overrides:
        claims.update(claim_overrides)
    token = jwt.encode(
        claims,
        private,
        algorithm="RS256",
        headers={"kid": "kid-1", "typ": "clayseal-svid+jwt"},
    )
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public))
    jwk.update({"kid": "kid-1", "alg": "RS256", "use": "sig"})
    return token, {"keys": [jwk]}


def test_verify_offline_normalizes_to_agent_claims():
    token, jwks = _token_and_jwks()

    claims = verify_offline(token, jwks=jwks, issuer="clayseal.io", audience="acme")
    identity = AgentIdentityClaims.from_claims(claims)

    assert identity.agent_id == "agent-1"
    assert identity.principal == "alice@example.com"
    assert identity.confirmation_thumbprint == "thumbprint"


def test_fastapi_dependency_verifies_bearer_token():
    token, jwks = _token_and_jwks()
    verifier = AgentIdentityVerifier(jwks=jwks, issuer="clayseal.io", audience="acme")

    identity = verifier(f"Bearer {token}")

    assert identity.agent_type == "researcher"
    assert identity.subject.startswith("spiffe://")


def test_mcp_and_langchain_helpers_attach_identity_metadata():
    class Session:
        token = "abc"
        agent_id = "agent-1"
        agent_type = "researcher"
        owner = "alice@example.com"
        credential = type("Credential", (), {"spiffe_id": "spiffe://agent"})()

    session = Session()
    assert authorization_header(session) == {"Authorization": "Bearer abc"}
    assert identity_metadata(session)["agent_id"] == "agent-1"

    config = identity_config(session, {"metadata": {"existing": True}})
    assert config["metadata"]["existing"] is True
    assert config["metadata"]["agent_id"] == "agent-1"
    assert config["headers"]["Authorization"] == "Bearer abc"


def test_langchain_wrapper_injects_config():
    class Runnable:
        def invoke(self, value, config=None, **_kwargs):
            return {"value": value, "config": config}

    wrapped = with_agent_identity(Runnable(), "token")
    result = wrapped.invoke("hello", config={"metadata": {"x": 1}})

    assert result["value"] == "hello"
    assert result["config"]["metadata"]["clayseal.identity"] is True
    assert result["config"]["headers"]["Authorization"] == "Bearer token"
