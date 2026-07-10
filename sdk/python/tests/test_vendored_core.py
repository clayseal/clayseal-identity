"""Vendored-core guarantees (``clayseal/_core.py``).

Two concerns:

1. **Behavior of the CLAYSEAL_*-keyed production guards.** The guards used to
   live in the internal core package keyed to ``AGENTAUTH_ENV``, so after the
   env-var rename they silently no-opped under ``CLAYSEAL_ENV=production``.
   These tests pin the fixed behavior.

2. **Parity with the ``agentauth.core`` originals** for the helpers whose
   semantics are shared with the upper Clay Seal layers (canonical JSON,
   path-scope matching). These tests run only where the internal core package
   is installed (internal CI's ``core-parity`` job) and skip everywhere else.
"""
from __future__ import annotations

import pytest

from clayseal import _core
from clayseal.identity.models import Credential

# --------------------------------------------------------------------------- #
# production guards (CLAYSEAL_ENV)
# --------------------------------------------------------------------------- #


def test_guards_inactive_outside_production(monkeypatch):
    monkeypatch.setenv("CLAYSEAL_ENV", "development")
    monkeypatch.setenv("CLAYSEAL_DEV_ATTESTOR", "1")
    assert _core.production_violations() == []
    _core.refuse_dev_attestation_client(dev_attestation_enabled=True)  # no raise


def test_refuses_dev_attestation_in_production(monkeypatch):
    """Regression: this refusal previously keyed off AGENTAUTH_ENV and no-opped
    under CLAYSEAL_ENV=production."""
    monkeypatch.setenv("CLAYSEAL_ENV", "production")
    with pytest.raises(RuntimeError, match="dev_attestation is not permitted"):
        _core.refuse_dev_attestation_client(dev_attestation_enabled=True)


def test_refuses_remote_dev_attestor_escape_hatch_in_production(monkeypatch):
    monkeypatch.setenv("CLAYSEAL_ENV", "production")
    monkeypatch.setenv("CLAYSEAL_ALLOW_REMOTE_DEV_ATTESTOR", "1")
    with pytest.raises(RuntimeError, match="CLAYSEAL_ALLOW_REMOTE_DEV_ATTESTOR"):
        _core.refuse_dev_attestation_client(dev_attestation_enabled=False)


def test_client_constructor_refuses_dev_attestation_in_production(monkeypatch):
    from clayseal.identity import ClaySeal

    monkeypatch.setenv("CLAYSEAL_ENV", "production")
    with pytest.raises(RuntimeError, match="dev_attestation is not permitted"):
        ClaySeal(api_key="cs_test", dev_attestation=True)


def test_production_violations_flag_missing_admin_key_and_cors(monkeypatch):
    monkeypatch.setenv("CLAYSEAL_ENV", "production")
    monkeypatch.delenv("CLAYSEAL_ADMIN_API_KEY", raising=False)
    monkeypatch.delenv("CLAYSEAL_CORS_ORIGINS", raising=False)
    violations = "; ".join(_core.production_violations())
    assert "CLAYSEAL_ADMIN_API_KEY" in violations
    assert "CLAYSEAL_CORS_ORIGINS" in violations


def test_production_violations_reject_wildcard_cors_and_dev_attestor(monkeypatch):
    monkeypatch.setenv("CLAYSEAL_ENV", "production")
    monkeypatch.setenv("CLAYSEAL_ADMIN_API_KEY", "k")
    monkeypatch.setenv("CLAYSEAL_CORS_ORIGINS", "*")
    monkeypatch.setenv("CLAYSEAL_DEV_ATTESTOR", "1")
    violations = "; ".join(_core.production_violations())
    assert "must not include '*'" in violations
    assert "CLAYSEAL_DEV_ATTESTOR" in violations
    with pytest.raises(RuntimeError, match="refused to start"):
        _core.enforce_production_policy()


def test_clean_production_env_passes(monkeypatch):
    monkeypatch.setenv("CLAYSEAL_ENV", "production")
    monkeypatch.setenv("CLAYSEAL_ADMIN_API_KEY", "k")
    monkeypatch.setenv("CLAYSEAL_CORS_ORIGINS", "https://dashboard.example.com")
    monkeypatch.delenv("CLAYSEAL_DEV_ATTESTOR", raising=False)
    monkeypatch.delenv("CLAYSEAL_ALLOW_REMOTE_DEV_ATTESTOR", raising=False)
    _core.enforce_production_policy()  # no raise


# --------------------------------------------------------------------------- #
# receipts seam: Credential.to_binding_dict
# --------------------------------------------------------------------------- #

# The exact key set wrap_agentauth_session -> AuthorityBinding.from_agentauth_credential
# consumes in the receipts layer. Changing it is a cross-repo API break.
_BINDING_KEYS = {
    "agent_id", "spiffe_id", "agent_type", "owner", "scopes", "selectors",
    "expires_at", "capabilities", "biscuit", "has_biscuit", "bound_keyhash",
}


def test_to_binding_dict_keeps_the_receipts_contract():
    cred = Credential(
        agent_id="agent-1",
        token="t",
        spiffe_id="spiffe://clayseal.io/customer/acme/agent/researcher",
        agent_type="researcher",
        owner="alice@acme.ai",
        scopes=["db:read"],
        selectors=["env:test"],
        expires_at="2027-01-01T00:00:00Z",
        capabilities=[{"resource": "db", "action": "read"}],
        biscuit="b64",
        bound_keyhash="kh",
    )
    binding = cred.to_binding_dict()
    assert set(binding) == _BINDING_KEYS
    assert binding["has_biscuit"] is True
    assert binding["scopes"] == ["db:read"]


# --------------------------------------------------------------------------- #
# parity with agentauth.core (skips when core is not installed)
# --------------------------------------------------------------------------- #

try:
    from agentauth.core import hash_util as core_hash
    from agentauth.core import path_matching as core_paths
except ImportError:  # public checkouts: core is internal-only
    core_hash = core_paths = None

needs_core = pytest.mark.skipif(
    core_hash is None, reason="internal agentauth-core not installed"
)

_JSON_CORPUS = [
    {"b": 1, "a": [2, {"z": None, "y": "ü"}], "c": True},
    [],
    {"nested": {"deep": {"list": [1, 2, 3], "s": "a/b\\c"}}},
    "plain string",
    3.14,
]

_PATH_CORPUS = [
    "src/app.py",
    "./src/app.py",
    "src//app.py",
    "src/../secrets/key.pem",
    "../escape.txt",
    "/absolute/path",
    "..",
    r"windows\style\path.txt",
    " padded/path.txt ",
]

_PATTERNS = [
    ["src/*"],
    ["src/*", "docs/**"],
    ["*.pem"],
    [" spaced/* "],
    [],
]


@needs_core
@pytest.mark.parametrize("value", _JSON_CORPUS)
def test_canonical_json_parity(value):
    assert _core.canonical_json_bytes(value) == core_hash.canonical_json_bytes(value)


@needs_core
@pytest.mark.parametrize("path", _PATH_CORPUS)
def test_path_normalization_parity(path):
    assert _core.normalize_path(path) == core_paths.normalize_path(path)
    assert _core.path_escapes_root(path) == core_paths.path_escapes_root(path)


@needs_core
@pytest.mark.parametrize("path", _PATH_CORPUS)
@pytest.mark.parametrize("patterns", _PATTERNS)
def test_path_matching_parity(path, patterns):
    assert _core.path_matches_any(path, patterns) == core_paths.path_matches_any(
        path, patterns
    )
    assert _core.evaluate_path_scope(
        path, allowed_paths=patterns, denied_paths=["secrets/*"]
    ) == core_paths.evaluate_path_scope(
        path, allowed_paths=patterns, denied_paths=["secrets/*"]
    )
