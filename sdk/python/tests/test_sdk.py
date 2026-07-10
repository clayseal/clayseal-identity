"""End-to-end SDK tests against the in-process backend (identity surface)."""
from __future__ import annotations

import pytest

from clayseal.identity import AgentSession
from clayseal.identity.errors import AgentRevokedError


# --------------------------------------------------------------------------- #
# identify
# --------------------------------------------------------------------------- #
def test_identify_returns_session(auth):
    agent = auth.identify(
        agent_type="researcher", owner="alice@acme.ai", scopes=["db:read"]
    )
    assert isinstance(agent, AgentSession)
    assert agent.agent_id
    assert agent.token.count(".") == 2
    assert agent.scopes == ["db:read"]
    assert agent.agent_type == "researcher"
    assert agent.owner == "alice@acme.ai"


def test_session_from_token_rehydrates(auth):
    agent = auth.identify(agent_type="researcher", owner="a@b.c", scopes=["db:read"])
    rehydrated = auth.session_from_token(
        {
            "agent_id": agent.agent_id,
            "token": agent.token,
            "spiffe_id": agent.credential.spiffe_id,
            "agent_type": agent.agent_type,
            "owner": agent.owner,
            "scopes": agent.scopes,
            "selectors": agent.credential.selectors,
            "expires_at": agent.credential.expires_at,
        }
    )
    assert rehydrated.agent_id == agent.agent_id
    assert rehydrated.token == agent.token


# --------------------------------------------------------------------------- #
# validate
# --------------------------------------------------------------------------- #
def test_validate_token(auth):
    agent = auth.identify(agent_type="researcher", owner="a@b.c", scopes=["db:read"])
    # identify() issues a sender-constrained (PoP-bound) token, so validation
    # goes through the session, which proves possession with the workload key.
    result = agent.validate()
    assert result.valid is True
    assert result.claims["agent_id"] == agent.agent_id
    assert result.claims["sub"] == agent.credential.spiffe_id


def test_session_validate(auth):
    agent = auth.identify(agent_type="researcher", owner="a@b.c", scopes=["db:read"])
    result = agent.validate()
    assert result.valid is True


# --------------------------------------------------------------------------- #
# revocation
# --------------------------------------------------------------------------- #
def test_revoke_invalidates_token(auth):
    agent = auth.identify(agent_type="researcher", owner="a@b.c", scopes=["db:read"])
    agent.revoke()
    with pytest.raises(AgentRevokedError):
        auth.validate(agent.token)


# --------------------------------------------------------------------------- #
# admin reads
# --------------------------------------------------------------------------- #
def test_agents_listing_and_lookup(auth):
    agent = auth.identify(agent_type="researcher", owner="a@b.c", scopes=["db:read"])
    agents = auth.agents()
    ids = {a.id for a in agents}
    assert agent.agent_id in ids

    info = auth.agent(agent.agent_id)
    assert info.id == agent.agent_id
    assert info.agent_type == "researcher"
    assert info.status == "active"


# --------------------------------------------------------------------------- #
# X.509-SVID (mTLS)
# --------------------------------------------------------------------------- #
def test_identify_can_request_x509_svid(auth, base_url):
    import ssl

    from cryptography import x509

    session = auth.identify(
        agent_type="researcher", owner="a@b.c", capabilities=[{"resource": "db", "action": "read"}],
        request_x509=True,
    )
    chain = session.x509_svid_chain
    assert chain and "BEGIN CERTIFICATE" in chain
    leaf = x509.load_pem_x509_certificate(chain.encode())
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.UniformResourceIdentifier) == [session.credential.spiffe_id]
    # The session can build a working mTLS context from the SVID + fetched bundle.
    ctx = session.mtls_context(purpose=ssl.Purpose.SERVER_AUTH)
    assert isinstance(ctx, ssl.SSLContext)


def test_identify_without_x509_has_no_svid(auth):
    session = auth.identify(agent_type="researcher", owner="a@b.c", scopes=["db:read"])
    assert session.x509_svid_chain is None
