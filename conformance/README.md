# Clay Seal Identity Conformance

This directory is the public entry point for Clay Seal Identity conformance.
The executable tests live in `backend/tests/test_federation.py` because they
mint fresh short-lived credentials from the real service rather than shipping
expired static JWTs.

Run:

```bash
pytest backend/tests/test_federation.py -q
```

The token profile is documented in `docs/CONFORMANCE.md`.
