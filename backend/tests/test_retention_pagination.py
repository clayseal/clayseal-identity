"""Bounded listing + retention (High 10): list_agents pagination and the
prune_expired retention primitive."""
from __future__ import annotations

import uuid
from datetime import timedelta

from agentauth.backend.db import SessionLocal
from agentauth.backend.models import AttestationUse, CapabilityChallenge, new_id, utcnow
from agentauth.backend.retention import prune_expired
from tests.attest import register_and_identify


def test_list_agents_is_paginated(client, customer):
    h = customer["headers"]
    for i in range(3):
        resp = register_and_identify(
            client, h, agent_type=f"pag-agent-{i}", scopes=["db:read"]
        )
        assert resp.status_code == 200, resp.text

    page = client.get("/v1/agents?limit=2&offset=0", headers=h)
    assert page.status_code == 200
    assert len(page.json()) == 2

    page2 = client.get("/v1/agents?limit=2&offset=2", headers=h)
    assert page2.status_code == 200
    assert len(page2.json()) >= 1


def test_list_agents_rejects_out_of_range_limits(client, customer):
    h = customer["headers"]
    assert client.get("/v1/agents?limit=0", headers=h).status_code == 422
    assert client.get("/v1/agents?limit=1001", headers=h).status_code == 422
    assert client.get("/v1/agents?offset=-1", headers=h).status_code == 422


def test_prune_expired_removes_stale_rows(customer):
    cid = customer["customer_id"]
    past = utcnow() - timedelta(hours=1)
    with SessionLocal() as db:
        db.add(AttestationUse(customer_id=cid, jti=uuid.uuid4().hex, expires_at=past))
        db.add(
            CapabilityChallenge(
                id=new_id(),
                customer_id=cid,
                challenge="stale-" + uuid.uuid4().hex,
                expires_at=past,
            )
        )
        db.commit()

    with SessionLocal() as db:
        summary = prune_expired(db)

    assert summary["attestation_uses"] >= 1
    assert summary["capability_challenges"] >= 1
    assert "agents" in summary


def test_prune_keeps_unexpired_rows(customer):
    cid = customer["customer_id"]
    future = utcnow() + timedelta(hours=1)
    live_jti = uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(AttestationUse(customer_id=cid, jti=live_jti, expires_at=future))
        db.commit()

    with SessionLocal() as db:
        prune_expired(db)

    with SessionLocal() as db:
        from sqlalchemy import select

        still_there = db.scalar(
            select(AttestationUse).where(AttestationUse.jti == live_jti)
        )
    assert still_there is not None
