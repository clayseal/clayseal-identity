"""Attestation document size cap (Medium 12).

A per-field max_length bounds parse/verify work on a single request; a global
request body-size limit still belongs at the edge (documented in schemas).
"""
from __future__ import annotations

from clayseal.backend.schemas import MAX_ATTESTATION_DOCUMENT_CHARS


def test_oversized_attestation_document_rejected(client, customer):
    oversized = "a" * (MAX_ATTESTATION_DOCUMENT_CHARS + 1)
    resp = client.post(
        "/v1/identify",
        json={"attestation_document": oversized},
        headers=customer["headers"],
    )
    assert resp.status_code == 422


def test_reasonably_sized_document_passes_validation(client, customer):
    # A within-limit (but bogus) document passes schema validation and is then
    # rejected by attestation logic (403), not by the size guard (422).
    resp = client.post(
        "/v1/identify",
        json={"attestation_document": "a.b.c"},
        headers=customer["headers"],
    )
    assert resp.status_code != 422
