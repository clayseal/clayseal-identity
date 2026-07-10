"""Developer diagnostics for agent identity adoption."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from .profile import LintFinding, lint_summary, lint_token
from .verifier import verify_offline


@dataclass
class DiagnosticFinding:
    level: str
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"level": self.level, "code": self.code, "message": self.message}


def _finding(level: str, code: str, message: str) -> DiagnosticFinding:
    return DiagnosticFinding(level, code, message)


def doctor_token(
    token: str,
    *,
    jwks: dict[str, Any] | None = None,
    issuer: str | None = None,
    audience: str | None = None,
) -> list[DiagnosticFinding]:
    """Lint and optionally verify a token."""
    out = [
        DiagnosticFinding(f.level, f.code, f.message)
        for f in lint_token(token)
    ]
    if jwks is not None and issuer is not None:
        try:
            verify_offline(token, jwks=jwks, issuer=issuer, audience=audience)
        except Exception as exc:  # noqa: BLE001 - diagnostics should report all failures
            out.append(_finding("fail", "verify.offline", str(exc)))
        else:
            out.append(_finding("pass", "verify.offline", "offline JWKS verification passed"))
    else:
        out.append(
            _finding(
                "warn",
                "verify.skipped",
                "offline verification skipped; pass --jwks and --issuer",
            )
        )
    return out


def doctor_agent_identity_document(doc: dict[str, Any]) -> list[DiagnosticFinding]:
    """Validate a /.well-known/agent-identity.json-style document."""
    out: list[DiagnosticFinding] = []
    if doc.get("profile") == "clayseal-agent-identity-v1":
        out.append(_finding("pass", "metadata.profile", "agent identity profile is v1"))
    else:
        out.append(_finding("fail", "metadata.profile", "profile must be clayseal-agent-identity-v1"))
    if doc.get("issuer"):
        out.append(_finding("pass", "metadata.issuer", "issuer is present"))
    else:
        out.append(_finding("fail", "metadata.issuer", "issuer is missing"))
    if doc.get("jwks_uri"):
        out.append(_finding("pass", "metadata.jwks_uri", "jwks_uri is present"))
    else:
        out.append(_finding("fail", "metadata.jwks_uri", "jwks_uri is missing"))
    if doc.get("proof_of_possession_required") is True:
        out.append(_finding("pass", "metadata.pop", "proof-of-possession is required"))
    else:
        out.append(_finding("warn", "metadata.pop", "proof_of_possession_required should be true"))
    ttl = doc.get("recommended_ttl_seconds")
    if isinstance(ttl, int) and ttl <= 900:
        out.append(_finding("pass", "metadata.ttl", f"recommended TTL is {ttl}s"))
    elif isinstance(ttl, int):
        out.append(_finding("warn", "metadata.ttl", f"recommended TTL is {ttl}s; prefer <=900s"))
    else:
        out.append(_finding("warn", "metadata.ttl", "recommended_ttl_seconds is missing"))
    return out


def preflight_endpoint(
    url: str,
    *,
    method: str = "GET",
    token: str | None = None,
    timeout: float = 10.0,
) -> list[DiagnosticFinding]:
    """Probe whether an HTTP endpoint rejects missing and malformed identity."""
    method = method.upper()
    out: list[DiagnosticFinding] = []
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        try:
            no_auth = client.request(method, url)
        except httpx.HTTPError as exc:
            return [_finding("fail", "endpoint.reachable", f"request failed: {exc}")]
        if no_auth.status_code in (401, 403):
            out.append(_finding("pass", "endpoint.no_auth", "missing token was rejected"))
        else:
            out.append(
                _finding(
                    "fail",
                    "endpoint.no_auth",
                    f"missing token returned HTTP {no_auth.status_code}; expected 401/403",
                )
            )
        try:
            malformed = client.request(method, url, headers={"Authorization": "Bearer not-a-jwt"})
        except httpx.HTTPError as exc:
            out.append(_finding("fail", "endpoint.malformed", f"malformed-token request failed: {exc}"))
            return out
        if malformed.status_code in (401, 403):
            out.append(_finding("pass", "endpoint.malformed", "malformed token was rejected"))
        else:
            out.append(
                _finding(
                    "fail",
                    "endpoint.malformed",
                    f"malformed token returned HTTP {malformed.status_code}; expected 401/403",
                )
            )
        if token:
            try:
                good = client.request(method, url, headers={"Authorization": f"Bearer {token}"})
            except httpx.HTTPError as exc:
                out.append(_finding("warn", "endpoint.token_path", f"token-bearing request failed: {exc}"))
                return out
            if good.status_code < 500:
                out.append(
                    _finding(
                        "pass",
                        "endpoint.token_path",
                        f"token-bearing request reached application path: HTTP {good.status_code}",
                    )
                )
            else:
                out.append(
                    _finding("warn", "endpoint.token_path", f"token-bearing request returned HTTP {good.status_code}")
                )
    return out


def scan_mcp_config(config: dict[str, Any]) -> list[DiagnosticFinding]:
    """Scan common MCP config shapes for identity/auth risks."""
    out: list[DiagnosticFinding] = []
    servers = config.get("mcpServers") or config.get("servers") or {}
    if not isinstance(servers, dict) or not servers:
        return [_finding("warn", "mcp.servers", "no MCP servers found in config")]

    for name, server in servers.items():
        if not isinstance(server, dict):
            out.append(_finding("warn", f"mcp.{name}.shape", "server entry is not an object"))
            continue
        url = str(server.get("url") or server.get("endpoint") or "")
        command = str(server.get("command") or "")
        headers = server.get("headers") or {}
        env = server.get("env") or {}
        prefix = f"mcp.{name}"
        if url.startswith("https://"):
            out.append(_finding("pass", f"{prefix}.transport", "remote server uses HTTPS"))
        elif url.startswith("http://"):
            out.append(_finding("fail", f"{prefix}.transport", "remote server uses plain HTTP"))
        elif command:
            out.append(_finding("warn", f"{prefix}.transport", "local command server; review filesystem/tool access"))
        else:
            out.append(_finding("warn", f"{prefix}.transport", "server transport is unclear"))

        auth_header = ""
        if isinstance(headers, dict):
            auth_header = str(headers.get("Authorization") or headers.get("authorization") or "")
        if auth_header.startswith("Bearer "):
            out.append(_finding("pass", f"{prefix}.auth", "Authorization bearer header configured"))
            token_value = auth_header.removeprefix("Bearer ").strip()
            looks_interpolated = any(marker in token_value for marker in ("$", "{{", "<", "%"))
            if token_value and not looks_interpolated:
                out.append(
                    _finding(
                        "warn",
                        f"{prefix}.auth_literal",
                        "bearer token appears literal in config; prefer an env placeholder",
                    )
                )
        elif url:
            out.append(_finding("warn", f"{prefix}.auth", "remote server has no obvious Authorization header"))
        else:
            out.append(_finding("warn", f"{prefix}.auth", "local server identity depends on process boundary"))

        if isinstance(env, dict):
            secret_keys = [k for k in env if any(word in k.upper() for word in ("TOKEN", "KEY", "SECRET"))]
            if secret_keys:
                out.append(
                    _finding(
                        "warn",
                        f"{prefix}.env_secrets",
                        f"environment passes possible secrets: {', '.join(sorted(secret_keys))}",
                    )
                )
    return out


def findings_payload(findings: list[DiagnosticFinding | LintFinding]) -> dict[str, Any]:
    as_lint = [
        LintFinding(f.level, f.code, f.message)
        for f in findings
    ]
    return {
        "summary": lint_summary(as_lint),
        "findings": [f.to_dict() for f in findings],
    }
