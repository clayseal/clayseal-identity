"""Retention / pruning of expired, no-longer-useful rows.

Three tables accumulate rows that are dead weight once past their expiry:

* ``attestation_uses`` — one-time replay records; useless once ``expires_at``
  passes (the underlying attestation document can no longer verify anyway).
* ``capability_challenges`` — one-time PoP nonces; useless once expired/used.
* ``agents`` — issued credentials; a credential whose ``expires_at`` is in the
  past can never validate again. We optionally drop *expired* rows older than a
  grace period, never ``revoked`` ones (kept for audit/revocation lookups) and
  never anything still valid.

This module provides the prune primitive. Scheduling it (a cron/EventBridge job,
a periodic task, or an ops script running ``python -m agentauth.backend.retention``)
is intentionally out of scope — wiring a scheduler is deployment-specific.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session

from .models import Agent, AttestationUse, CapabilityChallenge, utcnow


def prune_expired(db: Session, *, agent_grace_days: int = 30) -> dict[str, int]:
    """Delete expired one-time records and long-expired agents.

    Returns a ``{table: rows_deleted}`` summary. ``agent_grace_days`` keeps
    recently-expired agents around so the dashboard can still show them; set it
    to 0 to prune every expired (non-revoked) agent immediately.
    """
    now = utcnow()
    deleted: dict[str, int] = {}

    deleted["attestation_uses"] = db.execute(
        delete(AttestationUse).where(AttestationUse.expires_at <= now)
    ).rowcount

    deleted["capability_challenges"] = db.execute(
        delete(CapabilityChallenge).where(CapabilityChallenge.expires_at <= now)
    ).rowcount

    agent_cutoff = now - timedelta(days=agent_grace_days)
    deleted["agents"] = db.execute(
        delete(Agent).where(
            Agent.status == "expired",
            Agent.expires_at <= agent_cutoff,
        )
    ).rowcount

    db.commit()
    return deleted


def main() -> None:  # pragma: no cover - thin CLI wrapper
    """``python -m agentauth.backend.retention`` — prune once and report."""
    import json

    from .db import SessionLocal

    with SessionLocal() as db:
        summary = prune_expired(db)
    print(json.dumps({"pruned": summary}))


if __name__ == "__main__":  # pragma: no cover
    main()
