from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from agentauth.identity import explain_token, lint_token, verify_offline
from agentauth.identity.cli import main as cli_main
from agentauth.identity.integrations.fastapi import AgentIdentityVerifier
from agentauth.identity.integrations.langchain import identity_config, with_agent_identity
from agentauth.identity.integrations.mcp import authorization_header, identity_metadata
from agentauth.identity.profile import AgentIdentityClaims, lint_summary


def _rsa_keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


def _token_and_jwks():
    private, public = _rsa_keypair()
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": "agentauth.io",
            "sub": "spiffe://agentauth.io/customer/acme/agent/researcher",
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
        },
        private,
        algorithm="RS256",
        headers={"kid": "kid-1", "typ": "agentauth-svid+jwt"},
    )
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public))
    jwk.update({"kid": "kid-1", "alg": "RS256", "use": "sig"})
    return token, {"keys": [jwk]}


def test_profile_lint_and_explain_accept_good_agent_token():
    token, _jwks = _token_and_jwks()

    findings = lint_token(token)
    summary = lint_summary(findings)
    explained = explain_token(token)

    assert summary["fail"] == 0
    assert explained["identity"]["agent_id"] == "agent-1"
    assert explained["ttl_seconds"] == 300


def test_verify_offline_normalizes_to_agent_claims():
    token, jwks = _token_and_jwks()

    claims = verify_offline(token, jwks=jwks, issuer="agentauth.io", audience="acme")
    identity = AgentIdentityClaims.from_claims(claims)

    assert identity.agent_id == "agent-1"
    assert identity.principal == "alice@example.com"
    assert identity.confirmation_thumbprint == "thumbprint"


def test_cli_lint_and_verify(tmp_path, capsys):
    token, jwks = _token_and_jwks()
    token_path = tmp_path / "token.jwt"
    jwks_path = tmp_path / "jwks.json"
    token_path.write_text(token)
    jwks_path.write_text(json.dumps(jwks))

    assert cli_main(["lint", str(token_path)]) == 0
    assert cli_main(
        [
            "verify",
            str(token_path),
            "--jwks",
            str(jwks_path),
            "--issuer",
            "agentauth.io",
            "--audience",
            "acme",
        ]
    ) == 0
    out = capsys.readouterr().out
    assert "claim.cnf.jkt" in out
    assert '"valid": true' in out


def test_fastapi_dependency_verifies_bearer_token():
    token, jwks = _token_and_jwks()
    verifier = AgentIdentityVerifier(jwks=jwks, issuer="agentauth.io", audience="acme")

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
