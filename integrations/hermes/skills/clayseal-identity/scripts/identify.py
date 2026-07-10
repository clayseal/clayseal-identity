#!/usr/bin/env python3
"""Mint a Clay Seal credential and print the headers to send to a tool server.

Used by the `clayseal-identity` Hermes skill. Reads CLAYSEAL_BASE_URL and
CLAYSEAL_API_KEY from the environment; prints a JSON object of HTTP headers.

    python scripts/identify.py --owner me@acme.ai \
        --capability tool:search_web --server-url https://tools.acme.ai/mcp
"""
from __future__ import annotations

import argparse
import json
import os
import sys


def _parse_capability(spec: str) -> dict[str, str]:
    if ":" not in spec:
        raise argparse.ArgumentTypeError(
            f"capability must be resource:action, got {spec!r} "
            "(tool calls use tool:<tool_name>)"
        )
    resource, action = spec.split(":", 1)
    return {"resource": resource, "action": action}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", required=True, help="human or service that owns this agent")
    parser.add_argument("--agent-type", default="assistant")
    parser.add_argument(
        "--capability",
        action="append",
        type=_parse_capability,
        default=[],
        metavar="RESOURCE:ACTION",
        help="capability to grant (repeatable); tool calls use tool:<name>",
    )
    parser.add_argument(
        "--path",
        action="append",
        default=[],
        metavar="GLOB",
        help="restrict file tools to these path patterns (attenuation)",
    )
    parser.add_argument(
        "--deny-path",
        action="append",
        default=[],
        metavar="GLOB",
        help="paths file tools may never touch (attenuation)",
    )
    parser.add_argument(
        "--server-url",
        help="tool server MCP endpoint; include to add the proof-of-possession header",
    )
    parser.add_argument("--ttl-seconds", type=int, default=3600)
    args = parser.parse_args()

    base_url = os.environ.get("CLAYSEAL_BASE_URL")
    api_key = os.environ.get("CLAYSEAL_API_KEY")
    if not base_url or not api_key:
        print(
            "error: set CLAYSEAL_BASE_URL and CLAYSEAL_API_KEY in the environment.",
            file=sys.stderr,
        )
        return 2

    try:
        from clayseal.identity import ClaySeal
        from clayseal.identity.integrations.mcp import tool_headers
    except ImportError:
        print(
            'error: the Clay Seal SDK is not installed. Run: pip install "clayseal-identity"',
            file=sys.stderr,
        )
        return 2

    if not args.capability:
        print("error: grant at least one --capability (e.g. tool:search_web).", file=sys.stderr)
        return 2

    with ClaySeal(api_key=api_key, base_url=base_url) as auth:
        session = auth.identify(
            agent_type=args.agent_type,
            owner=args.owner,
            capabilities=args.capability,
            ttl_seconds=args.ttl_seconds,
        )
        if args.path or args.deny_path:
            session = session.attenuate(
                path_patterns=args.path or None,
                denied_paths=args.deny_path or None,
            )
        headers = tool_headers(session, server_url=args.server_url) if args.server_url else tool_headers(session)

    print(json.dumps(headers, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
