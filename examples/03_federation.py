"""Federation walk-through: verify an ClaySeal JWT-SVID like an outsider would.

1. identify() an agent against the (embedded) backend
2. fetch the tenant's PUBLIC discovery documents (no API key)
3. verify the JWT-SVID with stock PyJWT — zero ClaySeal code on the verifier side
4. print the RFC 7523 exchange for Anthropic Workload Identity Federation
   (executed live only when ANTHROPIC_FEDERATION_URL is set)

Run: python examples/03_federation.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import httpx
import jwt as pyjwt
from common import bootstrap

auth, api_key, base_url = bootstrap("Federation demo")
agent = auth.identify(
    agent_type="researcher",
    owner="alice@acme.ai",
    scopes=["db:read"],
)
token = agent.token
# spiffe://<trust-domain>/customer/<tenant>/agent/<type> — the tenant segment
tenant = agent.credential.spiffe_id.split("/customer/")[1].split("/")[0]

# --- the outsider's view: public documents only ----------------------------- #
discovery = httpx.get(
    f"{base_url}/t/{tenant}/.well-known/openid-configuration"
).raise_for_status().json()
jwks = httpx.get(discovery["jwks_uri"]).raise_for_status().json()
print(f"[federation] issuer={discovery['issuer']} algs={discovery['id_token_signing_alg_values_supported']}")

header = pyjwt.get_unverified_header(token)
key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
claims = pyjwt.decode(
    token,
    key=pyjwt.algorithms.RSAAlgorithm.from_jwk(key),
    algorithms=["RS256"],
    issuer=discovery["issuer"],
    options={"verify_aud": False},
)
print(f"[federation] stock PyJWT verified sub={claims['sub']}")

bundle = httpx.get(f"{base_url}/t/{tenant}/spiffe-bundle.json").raise_for_status().json()
print(f"[federation] SPIFFE bundle: {len(bundle['keys'])} jwt-svid key(s), "
      f"sequence={bundle['spiffe_sequence']}")

# --- Anthropic Workload Identity Federation (RFC 7523) ---------------------- #
federation_url = os.getenv("ANTHROPIC_FEDERATION_URL", "https://api.anthropic.com/v1/oauth/token")
print("\n[federation] RFC 7523 exchange for Anthropic WIF:")
print(f"  POST {federation_url}")
print("  grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer")
print("  assertion=<this JWT-SVID, minted with aud=https://api.anthropic.com>")
if os.getenv("ANTHROPIC_FEDERATION_URL"):
    resp = httpx.post(
        federation_url,
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": token,
        },
    )
    print(f"  -> HTTP {resp.status_code}: {resp.text[:200]}")
else:
    print("  (set ANTHROPIC_FEDERATION_URL to run the live exchange)")
