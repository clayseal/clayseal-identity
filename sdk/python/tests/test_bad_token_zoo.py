"""Wire the bad-token-zoo fixtures into the profile linter so the unsafe token
shapes are actually asserted, not just documented. Each case is signed (the
linter does not verify signatures) and must surface its expected finding.
"""
from __future__ import annotations

import json
from pathlib import Path

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from clayseal.identity import lint_token

_ZOO = Path(__file__).resolve().parents[3] / "bad-token-zoo" / "cases.json"

# Each unsafe shape must surface at least this (level, code) finding.
EXPECTED = {
    "no-audience": ("fail", "claim.aud"),
    "no-cnf": ("fail", "claim.cnf.jkt"),
    "long-ttl": ("fail", "ttl.long"),
    "wrong-typ": ("fail", "header.typ"),
    "missing-agent-metadata": ("warn", "claim.agent_id"),
}

_CASES = json.loads(_ZOO.read_text())
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _sign(case: dict) -> str:
    header = dict(case["header"])
    alg = header.pop("alg", "RS256")
    return pyjwt.encode(case["claims"], _KEY, algorithm=alg, headers=header)


def test_zoo_matches_expectations():
    """Guard against drift: every zoo case has an expectation and vice versa."""
    assert set(_CASES) == set(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_zoo_case_is_flagged(name):
    level, code = EXPECTED[name]
    findings = {(f.level, f.code) for f in lint_token(_sign(_CASES[name]))}
    assert (level, code) in findings, f"{name}: expected {level}:{code}, got {sorted(findings)}"
