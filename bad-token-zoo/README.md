# Bad Token Zoo

These are intentionally unsafe agent identity shapes for demos, blog posts, and
CLI tests. They are stored as JSON claim/header templates instead of signed
JWTs because Clay Seal credentials are supposed to be short-lived.

Try:

```bash
clayseal-identity lint token.jwt
clayseal-identity doctor --token token.jwt --jwks jwks.json --issuer agentauth.io --audience acme
```

## Cases

- `no-audience` — token cannot be pinned to a verifier.
- `no-cnf` — bearer replay risk; no sender-constraining key thumbprint.
- `long-ttl` — token lifetime is too long for an agent.
- `wrong-typ` — token type is not an agent identity token.
- `missing-agent-metadata` — technically verifiable, but bad for debugging and logs.
