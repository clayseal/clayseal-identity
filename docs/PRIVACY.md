# Clay Seal Identity Privacy and Data Handling

This document describes the data handled by Clay Seal Identity, the layer that
issues and verifies agent credentials. It is developer guidance for security,
privacy, and platform reviews; production deployments still need a
customer-specific legal privacy policy and data processing agreement where
applicable.

## Data This Layer Handles

Clay Seal Identity may process or store:

- Agent identifiers, SPIFFE IDs, trust domains, issuers, audiences, and subjects.
- Human or service principals associated with an agent session.
- Credential issuance, expiry, and verification timestamps.
- Public keys, key IDs, signing metadata, and proof-of-possession confirmation
  claims.
- Customer or tenant identifiers used to partition identity records.
- Optional API-key metadata for hosted identity service customers.
- Operational audit metadata, request IDs, and error categories.

It should not store prompts, model outputs, tool payloads, source code, or full
business transaction bodies. Pass those to upper layers only when needed for a
receipt or policy decision.

## Secrets

Treat the following as secrets:

- Agent private keys and persisted agent certificate files.
- Identity service signing keys and KMS credentials.
- Admin API keys, customer API keys, database URLs, and migration credentials.
- Bearer tokens, JWT-SVIDs, and any credential with a live `exp` window.

Never log these values. Redact them in exceptions, structured logs, traces, and
support bundles.

## Storage and Retention

Development defaults are intentionally lightweight. Production deployments
should use Postgres, run migrations explicitly, encrypt sensitive columns or
secrets at rest, and define retention for identity audit records.

Recommended defaults:

- Keep credentials short-lived, typically 5 to 15 minutes.
- Retain issuance and verification audit metadata only as long as required for
  security investigations and compliance.
- Rotate signing keys with an overlap period long enough for existing
  short-lived credentials to expire.
- Delete persisted agent keys when an agent is decommissioned.

## Data Minimization

- Use stable principal IDs instead of full profile records.
- Use tenant IDs and resource references instead of embedding customer payloads.
- Send only verified claims needed by capabilities or receipts.
- Prefer hashes or references for sensitive input binding.

## Production Controls

- Run the hosted service behind TLS.
- Pin issuer and audience on verifiers.
- Enable mTLS or equivalent network controls for service-to-service issuance.
- Store signing keys in KMS or HSM where policy requires it.
- Restrict CORS and admin endpoints.
- Monitor credential issuance volume and failed verification rates.
