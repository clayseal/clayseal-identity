"""Friendly developer workflows for Clay Seal agent identity."""
from __future__ import annotations

import json
import time
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from .profile import explain_token, lint_summary, lint_token
from .verifier import verify_offline


AUTHORITY_FIELDS = (
    "iss",
    "sub",
    "aud",
    "agent_id",
    "agent_type",
    "owner",
    "principal",
    "scope",
    "scopes",
    "selectors",
    "cnf",
    "exp",
    "iat",
    "nbf",
    "jti",
)


def whoami_payload(token: str) -> dict[str, Any]:
    """Return a compact, human-oriented identity summary for a token."""
    explained = explain_token(token)
    identity = explained["identity"]
    findings = lint_token(token)
    summary = lint_summary(findings)
    warnings = [
        finding.to_dict()
        for finding in findings
        if finding.level in {"warn", "fail"}
    ]
    return {
        "agent_id": identity.get("agent_id"),
        "agent_type": identity.get("agent_type"),
        "principal": identity.get("principal"),
        "subject": identity.get("subject"),
        "issuer": identity.get("issuer"),
        "audience": identity.get("audience"),
        "scopes": identity.get("scopes", []),
        "selectors": identity.get("selectors", []),
        "ttl_seconds": explained.get("ttl_seconds"),
        "expires_at": identity.get("expires_at"),
        "proof_of_possession": bool(identity.get("confirmation_thumbprint")),
        "summary": summary,
        "warnings": warnings,
    }


def _normalize_value(value: Any) -> Any:
    if isinstance(value, list | tuple | set):
        return sorted(str(item) for item in value)
    if isinstance(value, dict):
        return {str(key): _normalize_value(value[key]) for key in sorted(value)}
    return value


def diff_token_payload(before: str, after: str) -> dict[str, Any]:
    """Compare two tokens and highlight authority-relevant claim changes."""
    before_exp = explain_token(before)
    after_exp = explain_token(after)
    before_claims = before_exp["claims"]
    after_claims = after_exp["claims"]
    before_header = before_exp["header"]
    after_header = after_exp["header"]
    changes: list[dict[str, Any]] = []

    for field in ("alg", "typ", "kid"):
        old = _normalize_value(before_header.get(field))
        new = _normalize_value(after_header.get(field))
        if old != new:
            changes.append(
                {
                    "field": f"header.{field}",
                    "before": old,
                    "after": new,
                    "risk": "verification behavior changed",
                }
            )

    for field in AUTHORITY_FIELDS:
        old = _normalize_value(before_claims.get(field))
        new = _normalize_value(after_claims.get(field))
        if old == new:
            continue
        risk = "identity metadata changed"
        if field in {"aud", "scope", "scopes", "selectors", "cnf"}:
            risk = "authority boundary changed"
        elif field in {"exp", "iat", "nbf"}:
            risk = "token lifetime changed"
        changes.append({"field": field, "before": old, "after": new, "risk": risk})

    return {
        "before": whoami_payload(before),
        "after": whoami_payload(after),
        "changed": bool(changes),
        "changes": changes,
    }


def generate_integration(framework: str) -> dict[str, Any]:
    """Return copy-pasteable starter snippets for common agent workflows."""
    key = framework.lower().replace("_", "-")
    snippets = {
        "fastapi": {
            "files": [
                {
                    "path": "app.py",
                    "language": "python",
                    "contents": """from fastapi import Depends, FastAPI
from agentauth.identity.integrations.fastapi import AgentIdentityVerifier

app = FastAPI()
verify_agent = AgentIdentityVerifier(
    jwks={\"keys\": [...]},
    issuer=\"https://identity.example.com\",
    audience=\"tools-api\",
)

@app.post(\"/tool\")
def run_tool(agent=Depends(verify_agent)):
    return {\"agent_id\": agent.agent_id, \"ok\": True}
""",
                }
            ],
            "next_steps": [
                "Replace jwks, issuer, and audience with your tenant values.",
                "Run `clayseal-identity preflight http://localhost:8000/tool --method POST`.",
            ],
        },
        "mcp": {
            "files": [
                {
                    "path": "mcp-config.json",
                    "language": "json",
                    "contents": """{
  \"mcpServers\": {
    \"secure-tools\": {
      \"url\": \"https://tools.example.com/mcp\",
      \"headers\": {
        \"Authorization\": \"Bearer ${CLAYSEAL_AGENT_TOKEN}\"
      }
    }
  }
}
""",
                }
            ],
            "next_steps": [
                "Set CLAYSEAL_AGENT_TOKEN from your agent runtime.",
                "Run `clayseal-identity scan-mcp mcp-config.json` before sharing the config.",
            ],
        },
        "gha": {
            "files": [
                {
                    "path": ".github/workflows/agent-identity.yml",
                    "language": "yaml",
                    "contents": """name: agent identity check
on: [push]
jobs:
  verify-agent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install agentauth-identity
      - run: clayseal-identity lint \"$CLAYSEAL_AGENT_TOKEN\" --json
        env:
          CLAYSEAL_AGENT_TOKEN: ${{ secrets.CLAYSEAL_AGENT_TOKEN }}
""",
                }
            ],
            "next_steps": [
                "Bind production tokens to repo, workflow, commit SHA, and deploy audience.",
                "Use `verify` instead of `lint` once JWKS discovery is configured.",
            ],
        },
        "express": {
            "files": [
                {
                    "path": "middleware.js",
                    "language": "javascript",
                    "contents": """export function requireAgentIdentity(req, res, next) {
  const header = req.headers.authorization || \"\";
  if (!header.startsWith(\"Bearer \")) {
    return res.status(401).json({ error: \"missing agent identity\" });
  }
  // Verify the JWT against your tenant JWKS before trusting claims.
  req.agentToken = header.slice(\"Bearer \".length);
  next();
}
""",
                }
            ],
            "next_steps": [
                "Wire your preferred JWT verifier to the tenant JWKS.",
                "Run `clayseal-identity preflight http://localhost:3000/tool --method POST`.",
            ],
        },
    }
    if key not in snippets:
        supported = ", ".join(sorted(snippets))
        raise ValueError(f"unsupported framework {framework!r}; choose one of: {supported}")
    return {"framework": key, **snippets[key]}


def replay_lab_payload() -> dict[str, Any]:
    """Build real signed example tokens for common agent identity failures."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public))
    jwks = {"keys": [{**jwk, "kid": "lab-key", "alg": "RS256", "use": "sig"}]}
    now = int(time.time())
    base_claims = {
        "iss": "https://identity.example.com",
        "sub": "spiffe://identity.example.com/customer/demo/agent/coding-assistant",
        "aud": "tools-api",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": "lab-good",
        "agent_id": "agent-demo",
        "agent_type": "coding-assistant",
        "owner": "alice@example.com",
        "scope": ["repo:read"],
        "selectors": ["local:demo"],
        "cnf": {"jkt": "demo-thumbprint"},
    }

    cases = [
        ("good", "A short-lived sender-constrained agent token.", dict(base_claims), "verify-pass"),
        (
            "missing-cnf",
            "Looks like a bearer token, so replay is easier.",
            {k: v for k, v in base_claims.items() if k != "cnf"} | {"jti": "lab-missing-cnf"},
            "verify-fail",
        ),
        (
            "wrong-audience",
            "Validly signed, but meant for a different verifier.",
            dict(base_claims, aud="payments-api", jti="lab-wrong-audience"),
            "verify-fail",
        ),
        (
            "long-ttl",
            "Lives far longer than an agent token should.",
            dict(base_claims, exp=now + 24 * 60 * 60, jti="lab-long-ttl"),
            "lint-fail",
        ),
    ]
    rendered = []
    for name, story, claims, expected in cases:
        token = jwt.encode(
            claims,
            private,
            algorithm="RS256",
            headers={"kid": "lab-key", "typ": "agentauth-svid+jwt"},
        )
        findings = lint_token(token)
        try:
            verify_offline(token, jwks=jwks, issuer=base_claims["iss"], audience=base_claims["aud"])
        except Exception as exc:  # noqa: BLE001 - lab output should explain failures
            verify = {"valid": False, "error": str(exc)}
        else:
            verify = {"valid": True, "error": ""}
        rendered.append(
            {
                "name": name,
                "story": story,
                "expected": expected,
                "token": token,
                "verify": verify,
                "summary": lint_summary(findings),
                "findings": [finding.to_dict() for finding in findings],
            }
        )
    return {
        "issuer": base_claims["iss"],
        "audience": base_claims["aud"],
        "jwks": jwks,
        "cases": rendered,
    }
