from __future__ import annotations

import json
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from clayseal.identity import explain_token, lint_token, verify_offline
from clayseal.identity.cli import _load_json
from clayseal.identity.cli import main as cli_main
from clayseal.identity.diagnostics import (
    doctor_agent_identity_document,
    doctor_token,
    findings_payload,
    preflight_endpoint,
    scan_mcp_config,
)
from clayseal.identity.integrations.fastapi import AgentIdentityVerifier
from clayseal.identity.integrations.langchain import identity_config, with_agent_identity
from clayseal.identity.integrations.mcp import authorization_header, identity_metadata
from clayseal.identity.profile import AgentIdentityClaims, lint_summary
from clayseal.identity.usability import (
    diff_token_payload,
    generate_integration,
    replay_lab_payload,
    whoami_payload,
)


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

    claims = verify_offline(token, jwks=jwks, issuer="clayseal.io", audience="acme")
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
            "clayseal.io",
            "--audience",
            "acme",
        ]
    ) == 0
    out = capsys.readouterr().out
    assert "claim.cnf.jkt" in out
    assert '"valid": true' in out


def test_doctor_and_scan_mcp_diagnostics():
    token, jwks = _token_and_jwks()
    findings = doctor_token(token, jwks=jwks, issuer="clayseal.io", audience="acme")
    payload = findings_payload(findings)
    assert payload["summary"]["fail"] == 0

    doc_findings = doctor_agent_identity_document(
        {
            "profile": "clayseal-agent-identity-v1",
            "issuer": "clayseal.io",
            "jwks_uri": "https://example.com/jwks.json",
            "proof_of_possession_required": True,
            "recommended_ttl_seconds": 300,
        }
    )
    assert findings_payload(doc_findings)["summary"]["fail"] == 0

    mcp_findings = scan_mcp_config(
        {
            "mcpServers": {
                "remote": {
                    "url": "http://example.com/mcp",
                    "headers": {},
                    "env": {"API_TOKEN": "secret"},
                }
            }
        }
    )
    codes = {f.code for f in mcp_findings}
    assert "mcp.remote.transport" in codes
    assert "mcp.remote.env_secrets" in codes


def test_cli_doctor_and_scan_mcp(tmp_path, capsys):
    token, jwks = _token_and_jwks()
    token_path = tmp_path / "token.jwt"
    jwks_path = tmp_path / "jwks.json"
    metadata_path = tmp_path / "agent-identity.json"
    mcp_path = tmp_path / "mcp.json"
    token_path.write_text(token)
    jwks_path.write_text(json.dumps(jwks))
    metadata_path.write_text(
        json.dumps(
            {
                "profile": "clayseal-agent-identity-v1",
                "issuer": "clayseal.io",
                "jwks_uri": "https://example.com/jwks.json",
                "proof_of_possession_required": True,
                "recommended_ttl_seconds": 300,
            }
        )
    )
    mcp_path.write_text(json.dumps({"mcpServers": {"local": {"command": "python"}}}))

    assert cli_main(
        [
            "doctor",
            "--token",
            str(token_path),
            "--jwks",
            str(jwks_path),
            "--issuer",
            "clayseal.io",
            "--audience",
            "acme",
            "--agent-identity",
            str(metadata_path),
        ]
    ) == 0
    assert cli_main(["scan-mcp", str(mcp_path)]) == 0
    out = capsys.readouterr().out
    assert "verify.offline" in out
    assert "mcp.local.transport" in out


def test_usability_helpers_summarize_diff_generate_and_lab():
    token, _jwks = _token_and_jwks()
    wider_token, _ = _token_and_jwks({"aud": "payments-api", "scope": ["repo:read", "repo:write"]})

    summary = whoami_payload(token)
    assert summary["agent_id"] == "agent-1"
    assert summary["proof_of_possession"] is True

    diff = diff_token_payload(token, wider_token)
    changed_fields = {change["field"] for change in diff["changes"]}
    assert {"aud", "scope"}.issubset(changed_fields)

    snippet = generate_integration("fastapi")
    assert snippet["files"][0]["path"] == "app.py"
    assert "AgentIdentityVerifier.dependency" in snippet["files"][0]["contents"]
    assert "Depends(require_agent)" in snippet["files"][0]["contents"]

    lab = replay_lab_payload()
    assert {case["name"] for case in lab["cases"]} == {"good", "missing-cnf", "wrong-audience", "long-ttl"}
    assert lab["jwks"]["keys"][0]["kid"] == "lab-key"
    by_name = {case["name"]: case for case in lab["cases"]}
    assert by_name["good"]["verify"]["valid"] is True
    assert by_name["wrong-audience"]["verify"]["valid"] is False


def test_cli_status_whoami_diff_generate_and_replay_lab(tmp_path, capsys, monkeypatch):
    token, _jwks = _token_and_jwks()
    wider_token, _ = _token_and_jwks({"scope": ["repo:read", "repo:write"]})
    token_path = tmp_path / "token.jwt"
    wider_path = tmp_path / "wider.jwt"
    token_path.write_text(token)
    wider_path.write_text(wider_token)
    monkeypatch.setenv("CLAYSEAL_AGENT_TOKEN", token)

    assert cli_main(["status"]) == 0
    assert cli_main(["whoami", str(token_path)]) == 0
    assert cli_main(["diff-token", str(token_path), str(wider_path)]) == 0
    assert cli_main(["generate", "mcp"]) == 0
    assert cli_main(["replay-lab"]) == 0
    out = capsys.readouterr().out
    assert "Clay Seal Identity status" in out
    assert "Clay Seal agent identity" in out
    assert '"field": "scope"' in out
    assert "CLAYSEAL_AGENT_TOKEN" in out
    assert '"name": "missing-cnf"' in out


def test_preflight_endpoint_is_importable():
    # Direct network preflight is intentionally covered by CLI behavior in real
    # use. Keep the pure function importable and failure-shaped without network.
    assert callable(preflight_endpoint)


def test_cli_refuses_remote_plain_http_json():
    try:
        _load_json("http://example.com/jwks.json")
    except ValueError as exc:
        assert "plain HTTP" in str(exc)
    else:
        raise AssertionError("expected non-local plain HTTP to be refused")


def test_mcp_scan_warns_on_literal_bearer_token():
    findings = scan_mcp_config(
        {
            "mcpServers": {
                "remote": {
                    "url": "https://example.com/mcp",
                    "headers": {"Authorization": "Bearer secret-token-value"},
                }
            }
        }
    )
    assert "mcp.remote.auth_literal" in {finding.code for finding in findings}


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
