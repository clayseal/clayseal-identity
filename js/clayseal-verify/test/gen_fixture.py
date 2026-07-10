#!/usr/bin/env python3
"""Mint a cross-language parity fixture with the Python SDK.

Boots the identity backend in-process, issues a real credential (full + an
attenuated variant), and writes the tokens plus the client headers
(`tool_headers`, including the proof-of-possession) to ``fixture.json``. The
Node parity tests (``parity.test.mjs``) then verify that ``@clayseal/verify``
accepts and rejects exactly what Python produced.

The proof-of-possession carries a freshness window (~5 min), so run the Node
tests right after generating the fixture:

    python test/gen_fixture.py test/fixture.json && npm test
"""
from __future__ import annotations

import json
import logging
import os
import socket
import sys
import tempfile
import threading
import time


def main(out_path: str) -> None:
    os.environ.setdefault(
        "CLAYSEAL_DATABASE_URL", f"sqlite:///{tempfile.mkdtemp()}/agents.db"
    )
    logging.disable(logging.WARNING)

    import httpx
    import uvicorn

    from clayseal.backend.main import app
    from clayseal.identity import ClaySeal
    from clayseal.identity.integrations.mcp import (
        BISCUIT_HEADER,
        POP_HEADER,
        tool_headers,
    )

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical")
    )
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)

    base = f"http://127.0.0.1:{port}"
    tenant = ClaySeal.create_tenant("JS Parity", base_url=base)
    auth = ClaySeal(api_key=tenant["api_key"], base_url=base, dev_attestation=True)
    caps = [
        {"resource": "tool", "action": "search_web"},
        {"resource": "tool", "action": "read_docs"},
    ]
    session = auth.identify(agent_type="assistant", owner="js@parity.test", capabilities=caps)
    claims = session.validate().claims
    jwks = httpx.get(f"{base}/t/{claims['customer_id']}/jwks.json").json()
    narrowed = session.attenuate(
        capabilities=[{"resource": "tool", "action": "read_docs"}]
    )
    url = "https://tools.example.com/mcp"

    fixture = {
        "issuer": claims["iss"],
        "jwks": jwks,
        "token": session.token,
        "agent_id": session.agent_id,
        "biscuit": session.credential.biscuit,
        "biscuit_root_public_hex": session.credential.biscuit_root_public_key,
        "narrowed_biscuit": narrowed.credential.biscuit,
        "server_url": url,
        "headers": tool_headers(session, server_url=url),
        "narrowed_headers": tool_headers(narrowed, server_url=url),
        "pop_header_name": POP_HEADER,
        "biscuit_header_name": BISCUIT_HEADER,
    }
    with open(out_path, "w") as fh:
        json.dump(fixture, fh, indent=1)
    print(f"fixture written: {out_path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "test/fixture.json")
