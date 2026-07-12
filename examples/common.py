"""Shared bootstrap + console helpers for the ClaySeal examples.

Every example is a single, zero-config command:

    python examples/01_quickstart.py

`bootstrap()` gives you a ready-to-use `ClaySeal` bound to a fresh tenant. It
will:
  - use an already-running backend at CLAYSEAL_BASE_URL (or http://localhost:8000)
    if one is reachable, otherwise
  - boot the FastAPI backend in-process on a random port against a throwaway
    SQLite DB + audit log (so nothing touches your real data),
and then create a brand-new tenant and return the client.

The SDK and backend are imported straight from this repo (no install needed).
"""
from __future__ import annotations

import logging
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

# --- make the in-repo package importable without installing ----------------- #
_HERE = Path(__file__).resolve()
_REPO = _HERE.parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))


# --------------------------------------------------------------------------- #
# pretty console output
# --------------------------------------------------------------------------- #
class _C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    MAGENTA = "\033[35m"
    BLUE = "\033[34m"


def _supports_color() -> bool:
    return sys.stdout.isatty() and os.getenv("NO_COLOR") is None


def _c(text: str, color: str) -> str:
    return f"{color}{text}{_C.RESET}" if _supports_color() else text


def title(text: str) -> None:
    bar = "=" * max(8, len(text) + 4)
    print()
    print(_c(bar, _C.CYAN))
    print(_c(f"  {text}", _C.BOLD + _C.CYAN))
    print(_c(bar, _C.CYAN))


def step(text: str) -> None:
    print(_c(f"\n▸ {text}", _C.BOLD + _C.BLUE))


def info(text: str) -> None:
    print(f"  {text}")


def detail(text: str) -> None:
    print(_c(f"    {text}", _C.DIM))


def allow(text: str) -> None:
    print(_c(f"  ✓ {text}", _C.GREEN))


def deny(text: str) -> None:
    print(_c(f"  ✗ {text}", _C.RED))


def warn(text: str) -> None:
    print(_c(f"  ! {text}", _C.YELLOW))


def code(text: str) -> str:
    return _c(text, _C.MAGENTA)


# --------------------------------------------------------------------------- #
# backend bootstrap
# --------------------------------------------------------------------------- #
_EXPLICIT_URL = os.getenv("CLAYSEAL_BASE_URL")
_server_started = False


def _is_clayseal(base_url: str, timeout: float = 1.0) -> bool:
    """Confirm the URL is actually a Clay Seal backend (not just any server)."""
    import httpx

    try:
        resp = httpx.get(f"{base_url.rstrip('/')}/openapi.json", timeout=timeout)
        if resp.status_code != 200:
            return False
        return "/v1/customers" in resp.json().get("paths", {})
    except Exception:  # noqa: BLE001
        return False


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _boot_embedded() -> str:
    """Start the backend in-process against a throwaway DB; return its URL."""
    global _server_started
    tmp = tempfile.mkdtemp(prefix="clayseal-examples-")
    os.environ.setdefault("CLAYSEAL_DATABASE_URL", f"sqlite:///{tmp}/agents.db")
    os.environ.setdefault("CLAYSEAL_LOG_LEVEL", "WARNING")
    logging.getLogger("clayseal").setLevel(logging.WARNING)
    logging.getLogger("clayseal.access").setLevel(logging.CRITICAL)
    logging.getLogger("clayseal.backend.auth").setLevel(logging.CRITICAL)
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    import uvicorn

    from clayseal.backend.main import app  # noqa: WPS433 - imported after env is set

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()

    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("Embedded Clay Seal backend failed to start.")
    _server_started = True
    return f"http://127.0.0.1:{port}"


def ensure_backend() -> str:
    """Return a base URL for a Clay Seal backend.

    Uses CLAYSEAL_BASE_URL if it is set and points at a real Clay Seal backend;
    otherwise boots a throwaway one in-process (the default, zero-config path).
    """
    if _EXPLICIT_URL:
        if _is_clayseal(_EXPLICIT_URL):
            return _EXPLICIT_URL
        warn(f"CLAYSEAL_BASE_URL={_EXPLICIT_URL} is not a reachable Clay Seal backend; "
             "starting an embedded one instead.")
    return _boot_embedded()


def bootstrap(org_name: str = "Acme AI"):
    """Return (ClaySeal client bound to a fresh tenant, api_key, base_url)."""
    import logging

    from clayseal.identity import ClaySeal

    base_url = ensure_backend()
    if _server_started:
        detail(f"Started an embedded backend at {base_url} (throwaway data).")
    else:
        detail(f"Using the Clay Seal backend at {base_url}.")  # external, explicit

    tenant = ClaySeal.create_tenant(org_name, base_url=base_url)
    api_key = tenant["api_key"]
    detail(f"Created tenant {org_name!r}.")
    info(f"API key: {code(api_key)}")
    detail(f"API base URL: {base_url}")
    if _server_started:
        warn("Embedded backend — the dashboard won't see this data unless you set "
             "CLAYSEAL_BASE_URL to your running backend.")
    else:
        detail("Paste the API key into the dashboard Connect screen to view results.")
    client = ClaySeal(api_key=api_key, base_url=base_url, dev_attestation=True)

    # The SDK logs one structured line per identity operation (great in
    # production for Datadog/Grafana correlation). Quiet it here so the demo
    # narration is clean;
    # set CLAYSEAL_EXAMPLES_VERBOSE=1 to see it. (Done after the client is built
    # because constructing it configures the logger.)
    if not os.getenv("CLAYSEAL_EXAMPLES_VERBOSE"):
        logging.getLogger("clayseal").setLevel(logging.WARNING)
        logging.getLogger("clayseal.access").setLevel(logging.CRITICAL)
        logging.getLogger("clayseal.backend.auth").setLevel(logging.CRITICAL)

    return client, tenant["api_key"], base_url
