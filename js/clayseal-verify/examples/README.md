# Express verify example

A minimal [Express](https://expressjs.com/) server that protects an endpoint
with [`@clayseal/verify`](..).

## Run

```bash
cd js/clayseal-verify/examples
npm install

# Set your tenant's JWKS, issuer, and audience.
export CLAY_JWKS='{"keys":[...]}'
export CLAY_ISSUER=clayseal.io
export CLAY_AUDIENCE=my-tenant-id

npm start
```

The server exits with a clear message if any required env var is missing.

## Try it

```bash
# Replace <jwt> with a token from your Clay Seal identity service.
curl http://localhost:4000/verify -H "Authorization: Bearer <jwt>"
```

A missing or invalid token:

```bash
curl http://localhost:4000/verify
# → {"error":"missing or invalid Authorization header"}
```

## Where the values come from

| Env variable    | Source                                                |
|-----------------|-------------------------------------------------------|
| `CLAY_JWKS`     | `GET /t/{tenant}/jwks.json` on your Clay Seal service |
| `CLAY_ISSUER`   | Trust domain, e.g. `clayseal.io`                      |
| `CLAY_AUDIENCE` | Tenant / customer identifier                          |

Run the Python quickstart from the repo root (`python examples/01_quickstart.py`)
to see these values printed at startup.
