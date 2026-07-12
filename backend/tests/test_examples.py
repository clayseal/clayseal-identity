"""Smoke tests for the public examples."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _run_example(script: str, tmp_path: Path) -> str:
    env = os.environ.copy()
    env.pop("CLAYSEAL_BASE_URL", None)
    env.pop("CLAYSEAL_API_KEY", None)
    env["CLAYSEAL_DATABASE_URL"] = f"sqlite:///{tmp_path / f'{script}.db'}"
    env["CLAYSEAL_SIGNING_KEY_ENCRYPTION_KEY"] = (
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    )
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(REPO)
    result = subprocess.run(
        [sys.executable, str(REPO / "examples" / script)],
        cwd=REPO,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=45,
        check=False,
    )
    assert result.returncode == 0, result.stdout
    return result.stdout


def test_quickstart_example_runs(tmp_path):
    out = _run_example("01_quickstart.py", tmp_path)
    assert "Done - issue, validate, revoke in a handful of calls" in out


def test_capabilities_example_runs(tmp_path):
    out = _run_example("02_capabilities.py", tmp_path)
    assert "Done - express, attenuate, delegate, and verify rights offline" in out


def test_inspect_token_example_runs(tmp_path):
    out = _run_example("05_inspect_token.py", tmp_path)
    assert "Clay Seal token inspection (unverified)" in out
    assert "sender_constrained: yes" in out
