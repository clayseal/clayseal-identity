"""Command-line tools for the Clay Seal Identity OSS surface."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx

from .client import ClaySeal
from .diagnostics import (
    doctor_agent_identity_document,
    doctor_token,
    findings_payload,
    preflight_endpoint,
    scan_mcp_config,
)
from .profile import explain_token, lint_summary, lint_token
from .usability import (
    diff_token_payload,
    generate_integration,
    replay_lab_payload,
    whoami_payload,
)
from .verifier import verify_offline


def _read_token(value: str) -> str:
    if value == "-":
        return sys.stdin.read().strip()
    if value.count(".") == 2 and "/" not in value:
        return value.strip()
    path = Path(value)
    try:
        exists = path.exists()
    except OSError:
        exists = False
    if exists:
        return path.read_text().strip()
    return value.strip()


def _load_json(path_or_url: str) -> dict[str, Any]:
    if path_or_url.startswith(("https://", "http://")):
        return httpx.get(path_or_url, timeout=10.0).json()
    return json.loads(Path(path_or_url).read_text())


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def _print_kv(label: str, value: Any) -> None:
    if value in (None, "", []):
        value = "-"
    print(f"{label:22} {value}")


def cmd_explain(args: argparse.Namespace) -> int:
    _print_json(explain_token(_read_token(args.token)))
    return 0


def cmd_lint(args: argparse.Namespace) -> int:
    findings = lint_token(_read_token(args.token))
    if args.json:
        _print_json(
            {
                "summary": lint_summary(findings),
                "findings": [finding.to_dict() for finding in findings],
            }
        )
    else:
        for finding in findings:
            print(f"{finding.level.upper():4} {finding.code:20} {finding.message}")
    return 1 if any(f.level == "fail" for f in findings) else 0


def cmd_verify(args: argparse.Namespace) -> int:
    claims = verify_offline(
        _read_token(args.token),
        jwks=_load_json(args.jwks),
        issuer=args.issuer,
        audience=args.audience,
        require_cnf=not args.allow_bearer,
    )
    _print_json(claims if args.claims else {"valid": True, "agent_id": claims.get("agent_id")})
    return 0


def cmd_mint(args: argparse.Namespace) -> int:
    api_key = args.api_key
    if not api_key:
        tenant = ClaySeal.create_tenant(args.tenant, base_url=args.base_url)
        api_key = tenant["api_key"]
    auth = ClaySeal(
        api_key=api_key,
        base_url=args.base_url,
        dev_attestation=args.dev_attestation,
    )
    session = auth.identify(
        agent_type=args.agent_type,
        owner=args.owner,
        scopes=args.scope or [],
        ttl_seconds=args.ttl,
    )
    _print_json(
        {
            "agent_id": session.agent_id,
            "agent_type": session.agent_type,
            "owner": session.owner,
            "token": session.token,
            "expires_at": session.credential.expires_at,
            "warning": "dev_attestation is for localhost demos/tests only"
            if args.dev_attestation
            else "",
        }
    )
    auth.close()
    return 0


def cmd_conformance(args: argparse.Namespace) -> int:
    token = _read_token(args.token)
    findings = lint_token(token)
    claims = verify_offline(
        token,
        jwks=_load_json(args.jwks),
        issuer=args.issuer,
        audience=args.audience,
    )
    summary = lint_summary(findings)
    _print_json(
        {
            "valid": True,
            "summary": summary,
            "agent_id": claims.get("agent_id"),
            "findings": [finding.to_dict() for finding in findings],
        }
    )
    return 1 if summary["fail"] else 0


def cmd_doctor(args: argparse.Namespace) -> int:
    findings = []
    if args.agent_identity:
        findings.extend(doctor_agent_identity_document(_load_json(args.agent_identity)))
    if args.token:
        findings.extend(
            doctor_token(
                _read_token(args.token),
                jwks=_load_json(args.jwks) if args.jwks else None,
                issuer=args.issuer,
                audience=args.audience,
            )
        )
    if not findings:
        raise ValueError("doctor needs --token and/or --agent-identity")
    payload = findings_payload(findings)
    _print_json(payload)
    return 1 if payload["summary"]["fail"] else 0


def cmd_preflight(args: argparse.Namespace) -> int:
    findings = preflight_endpoint(
        args.url,
        method=args.method,
        token=_read_token(args.token) if args.token else None,
    )
    payload = findings_payload(findings)
    _print_json(payload)
    return 1 if payload["summary"]["fail"] else 0


def cmd_scan_mcp(args: argparse.Namespace) -> int:
    config = _load_json(args.config)
    findings = scan_mcp_config(config)
    payload = findings_payload(findings)
    _print_json(payload)
    return 1 if payload["summary"]["fail"] else 0


def cmd_status(args: argparse.Namespace) -> int:
    payload: dict[str, Any] = {
        "env": {
            "CLAYSEAL_AGENT_TOKEN": bool(os.environ.get("CLAYSEAL_AGENT_TOKEN")),
            "CLAYSEAL_API_KEY": bool(os.environ.get("CLAYSEAL_API_KEY")),
            "CLAYSEAL_IDENTITY_URL": os.environ.get("CLAYSEAL_IDENTITY_URL") or "",
        },
        "token": None,
        "mcp": None,
    }
    findings = []
    token = args.token or os.environ.get("CLAYSEAL_AGENT_TOKEN")
    if token:
        payload["token"] = whoami_payload(_read_token(token))
    if args.mcp:
        mcp_findings = scan_mcp_config(_load_json(args.mcp))
        payload["mcp"] = findings_payload(mcp_findings)
        findings.extend(mcp_findings)
    if args.json:
        _print_json(payload)
    else:
        print("Clay Seal Identity status")
        _print_kv("agent token", "present" if token else "missing")
        _print_kv("api key", "present" if payload["env"]["CLAYSEAL_API_KEY"] else "missing")
        _print_kv("identity url", payload["env"]["CLAYSEAL_IDENTITY_URL"])
        if payload["token"]:
            _print_kv("agent id", payload["token"]["agent_id"])
            _print_kv("agent type", payload["token"]["agent_type"])
            _print_kv("audience", payload["token"]["audience"])
            _print_kv("ttl seconds", payload["token"]["ttl_seconds"])
        if payload["mcp"]:
            _print_kv("mcp findings", payload["mcp"]["summary"])
    return 1 if any(f.level == "fail" for f in findings) else 0


def cmd_whoami(args: argparse.Namespace) -> int:
    payload = whoami_payload(_read_token(args.token))
    if args.json:
        _print_json(payload)
    else:
        print("Clay Seal agent identity")
        _print_kv("agent id", payload["agent_id"])
        _print_kv("agent type", payload["agent_type"])
        _print_kv("principal", payload["principal"])
        _print_kv("subject", payload["subject"])
        _print_kv("issuer", payload["issuer"])
        _print_kv("audience", payload["audience"])
        _print_kv("scopes", ", ".join(payload["scopes"]))
        _print_kv("selectors", ", ".join(payload["selectors"]))
        _print_kv("ttl seconds", payload["ttl_seconds"])
        _print_kv("proof of possession", "yes" if payload["proof_of_possession"] else "no")
        _print_kv("lint summary", payload["summary"])
        for warning in payload["warnings"]:
            print(f"{warning['level'].upper():4} {warning['code']:20} {warning['message']}")
    return 1 if payload["summary"]["fail"] else 0


def cmd_diff_token(args: argparse.Namespace) -> int:
    payload = diff_token_payload(_read_token(args.before), _read_token(args.after))
    _print_json(payload)
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    payload = generate_integration(args.framework)
    if args.json:
        _print_json(payload)
    else:
        print(f"Clay Seal {payload['framework']} starter")
        for file in payload["files"]:
            print(f"\n# {file['path']}")
            print(file["contents"].rstrip())
        if payload["next_steps"]:
            print("\nNext steps")
            for step in payload["next_steps"]:
                print(f"- {step}")
    return 0


def cmd_replay_lab(args: argparse.Namespace) -> int:
    payload = replay_lab_payload()
    _print_json(payload)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="clayseal-identity")
    sub = parser.add_subparsers(dest="command", required=True)

    explain = sub.add_parser("explain", help="Decode an agent token without verification")
    explain.add_argument("token", help="JWT string, path, or '-' for stdin")
    explain.set_defaults(func=cmd_explain)

    lint = sub.add_parser("lint", help="Lint a token for the Clay Seal agent identity profile")
    lint.add_argument("token", help="JWT string, path, or '-' for stdin")
    lint.add_argument("--json", action="store_true", help="Emit JSON")
    lint.set_defaults(func=cmd_lint)

    verify = sub.add_parser("verify", help="Verify a token offline using tenant JWKS")
    verify.add_argument("token", help="JWT string, path, or '-' for stdin")
    verify.add_argument("--jwks", required=True, help="JWKS JSON file or URL")
    verify.add_argument("--issuer", required=True)
    verify.add_argument("--audience")
    verify.add_argument("--claims", action="store_true", help="Print verified claims")
    verify.add_argument("--allow-bearer", action="store_true", help="Do not require cnf.jkt")
    verify.set_defaults(func=cmd_verify)

    mint = sub.add_parser("mint", help="Mint a localhost/dev agent identity")
    mint.add_argument("--base-url", default="http://localhost:8000")
    mint.add_argument("--api-key")
    mint.add_argument("--tenant", default="Clay Seal Dev")
    mint.add_argument("--agent-type", required=True)
    mint.add_argument("--owner", required=True)
    mint.add_argument("--scope", action="append", default=[])
    mint.add_argument("--ttl", type=int)
    mint.add_argument("--dev-attestation", action="store_true")
    mint.set_defaults(func=cmd_mint)

    conformance = sub.add_parser("conformance", help="Run profile lint + offline verification")
    conformance.add_argument("token", help="JWT string, path, or '-' for stdin")
    conformance.add_argument("--jwks", required=True, help="JWKS JSON file or URL")
    conformance.add_argument("--issuer", required=True)
    conformance.add_argument("--audience")
    conformance.set_defaults(func=cmd_conformance)

    doctor = sub.add_parser("doctor", help="Diagnose token and agent-identity metadata")
    doctor.add_argument("--token", help="JWT string, path, or '-' for stdin")
    doctor.add_argument("--jwks", help="JWKS JSON file or URL")
    doctor.add_argument("--issuer")
    doctor.add_argument("--audience")
    doctor.add_argument("--agent-identity", help="/.well-known/agent-identity.json file or URL")
    doctor.set_defaults(func=cmd_doctor)

    preflight = sub.add_parser("preflight", help="Probe whether an endpoint rejects unsafe identity")
    preflight.add_argument("url")
    preflight.add_argument("--method", default="GET")
    preflight.add_argument("--token", help="Optional valid token string/path for the happy path")
    preflight.set_defaults(func=cmd_preflight)

    scan_mcp = sub.add_parser("scan-mcp", help="Scan an MCP config for identity/auth risks")
    scan_mcp.add_argument("config", help="MCP JSON config file")
    scan_mcp.set_defaults(func=cmd_scan_mcp)

    status = sub.add_parser("status", help="Show local Clay Seal identity setup")
    status.add_argument("--token", help="JWT string, path, or '-' for stdin; defaults to CLAYSEAL_AGENT_TOKEN")
    status.add_argument("--mcp", help="Optional MCP JSON config to scan")
    status.add_argument("--json", action="store_true", help="Emit JSON")
    status.set_defaults(func=cmd_status)

    whoami = sub.add_parser("whoami", help="Show the agent described by a token")
    whoami.add_argument("token", help="JWT string, path, or '-' for stdin")
    whoami.add_argument("--json", action="store_true", help="Emit JSON")
    whoami.set_defaults(func=cmd_whoami)

    diff_token = sub.add_parser("diff-token", help="Compare identity and authority changes between two tokens")
    diff_token.add_argument("before", help="JWT string, path, or '-' for stdin")
    diff_token.add_argument("after", help="JWT string or path")
    diff_token.set_defaults(func=cmd_diff_token)

    generate = sub.add_parser("generate", help="Print starter integration snippets")
    generate.add_argument("framework", choices=["fastapi", "mcp", "gha", "express"])
    generate.add_argument("--json", action="store_true", help="Emit JSON")
    generate.set_defaults(func=cmd_generate)

    replay_lab = sub.add_parser("replay-lab", help="Generate signed example tokens for common identity failures")
    replay_lab.set_defaults(func=cmd_replay_lab)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001 - CLI should show concise failures
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
