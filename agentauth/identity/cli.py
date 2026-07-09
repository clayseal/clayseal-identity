"""Command-line tools for the Clay Seal Identity OSS surface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import httpx

from .client import AgentAuth
from .profile import explain_token, lint_summary, lint_token
from .verifier import verify_offline


def _read_token(value: str) -> str:
    if value == "-":
        return sys.stdin.read().strip()
    path = Path(value)
    if path.exists():
        return path.read_text().strip()
    return value.strip()


def _load_jwks(path_or_url: str) -> dict[str, Any]:
    if path_or_url.startswith(("https://", "http://")):
        return httpx.get(path_or_url, timeout=10.0).json()
    return json.loads(Path(path_or_url).read_text())


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


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
        jwks=_load_jwks(args.jwks),
        issuer=args.issuer,
        audience=args.audience,
        require_cnf=not args.allow_bearer,
    )
    _print_json(claims if args.claims else {"valid": True, "agent_id": claims.get("agent_id")})
    return 0


def cmd_mint(args: argparse.Namespace) -> int:
    api_key = args.api_key
    if not api_key:
        tenant = AgentAuth.create_tenant(args.tenant, base_url=args.base_url)
        api_key = tenant["api_key"]
    auth = AgentAuth(
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
        jwks=_load_jwks(args.jwks),
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
