"""05 - Inspect a Clay Seal identity token.

Run either:

    python examples/05_inspect_token.py
    python examples/05_inspect_token.py eyJ...

With no argument, this example starts the local demo backend, mints a token, and
prints what the token says. With an argument, it inspects that token instead.
Inspection is intentionally unverified; use verify_offline() or validate() for
enforcement.
"""
from __future__ import annotations

import sys

import common

from clayseal.identity import inspect_token


def _demo_token() -> str:
    auth, _api_key, _url = common.bootstrap("Acme AI")
    session = auth.identify(
        agent_type="docs-writer",
        owner="alice@acme.ai",
        capabilities=[
            {"resource": "repo", "action": "read"},
            {"resource": "docs", "action": "write"},
        ],
        ttl_seconds=900,
    )
    common.detail("Minted a throwaway demo token.")
    return session.token


def main() -> None:
    common.title("Clay Seal token inspector")
    token = sys.argv[1].strip() if len(sys.argv) > 1 else _demo_token()
    inspection = inspect_token(token)

    for line in inspection.summary_lines():
        common.info(line)

    common.warn("Inspection decodes claims only. Verify before trusting a token.")


if __name__ == "__main__":
    main()
