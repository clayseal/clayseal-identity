#!/usr/bin/env python3
"""One-shot migration: hash legacy plaintext tenant API keys."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from sqlalchemy import select

from clayseal.backend.api_keys import api_key_lookup_prefix, hash_api_key
from clayseal.backend.db import SessionLocal, init_db
from clayseal.backend.models import Customer


def migrate(*, dry_run: bool) -> int:
    init_db()
    migrated = 0
    skipped = 0
    with SessionLocal() as db:
        customers = list(db.scalars(select(Customer)).all())
        for customer in customers:
            if customer.api_key_hash:
                continue
            lookup = api_key_lookup_prefix(customer.api_key)
            if lookup is None:
                skipped += 1
                print(
                    f"skip customer_id={customer.id}: api_key is not a modern aa_<lookup>.<secret> value"
                )
                continue
            customer.api_key_hash = hash_api_key(customer.api_key)
            customer.api_key = lookup
            migrated += 1
            action = "would migrate" if dry_run else "migrated"
            print(f"{action} customer_id={customer.id} lookup_prefix={customer.api_key}")
        if dry_run:
            db.rollback()
        else:
            db.commit()
    print(f"done: {migrated} migrated, {skipped} skipped")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report rows that would be migrated without writing",
    )
    args = parser.parse_args()
    return migrate(dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
