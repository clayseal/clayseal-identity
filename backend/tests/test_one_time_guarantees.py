"""One-time guarantees under concurrency (High 5): attestation-use replay via a
UNIQUE constraint + insert-and-catch, and single-use challenge consumption via a
conditional UPDATE."""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from agentauth.backend import capabilities as cap
from agentauth.backend.attestation import record_attestation_use
from agentauth.backend.db import SessionLocal
from agentauth.backend.errors import AttestationDeniedError
from agentauth.backend.models import utcnow


def test_attestation_use_is_one_time(customer):
    cid = customer["customer_id"]
    jti = uuid.uuid4().hex
    expires_at = utcnow() + timedelta(minutes=5)

    with SessionLocal() as db:
        record_attestation_use(db, cid, jti=jti, expires_at=expires_at)
        db.commit()

    # Replaying the same (customer_id, jti) is rejected as a replay.
    with SessionLocal() as db:
        with pytest.raises(AttestationDeniedError, match="already been used"):
            record_attestation_use(db, cid, jti=jti, expires_at=expires_at)


def test_same_jti_allowed_for_different_customers(customer):
    # The UNIQUE is scoped to (customer_id, jti), so two tenants can independently
    # use the same jti.
    jti = uuid.uuid4().hex
    expires_at = utcnow() + timedelta(minutes=5)
    with SessionLocal() as db:
        record_attestation_use(db, customer["customer_id"], jti=jti, expires_at=expires_at)
        record_attestation_use(db, "other-customer-id", jti=jti, expires_at=expires_at)
        db.commit()  # no IntegrityError


def test_server_challenge_consumed_exactly_once(customer):
    cid = customer["customer_id"]
    with SessionLocal() as db:
        challenge = cap.issue_server_challenge(db, cid)

    with SessionLocal() as db:
        assert cap.consume_server_challenge(db, cid, challenge) is None
    with SessionLocal() as db:
        reason = cap.consume_server_challenge(db, cid, challenge)
    assert reason is not None and "already been used" in reason


def test_unknown_challenge_reports_reason(customer):
    with SessionLocal() as db:
        reason = cap.consume_server_challenge(db, customer["customer_id"], "not-a-real-challenge")
    assert reason is not None and "unknown" in reason


def test_expired_challenge_reports_reason(customer):
    cid = customer["customer_id"]
    from agentauth.backend.models import CapabilityChallenge, new_id

    challenge = "expired-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(
            CapabilityChallenge(
                id=new_id(),
                customer_id=cid,
                challenge=challenge,
                expires_at=utcnow() - timedelta(seconds=1),
            )
        )
        db.commit()
    with SessionLocal() as db:
        reason = cap.consume_server_challenge(db, cid, challenge)
    assert reason is not None and "expired" in reason
