"""Real cloud / Kubernetes node attestation.

Node attestation answers "does this workload genuinely run where it claims?"
before any credential is minted. These attestors verify *platform-signed
evidence* that a workload cannot forge without controlling the node:

- ``gcp_iit``  — a Google-signed instance identity token (JWT, RS256), verified
  against Google's public keys.
- ``k8s_psat`` — a Kubernetes projected service-account token, verified by the
  cluster's TokenReview API (which also returns the pod/service-account it is
  bound to).
- ``aws_iid``  — an EC2 instance identity document plus its RSA-2048 signature,
  verified against AWS's regional public certificate.

Unlike the static trust-anchor attestor (``clayseal/backend/attestation.py``),
which trusts a key an operator registered, these require no per-node secret: the
trust root is the cloud provider or the cluster itself.

Key binding. A verified node token proves the *node*, not the *presenter*. To
stop a token captured elsewhere (a log, a sidecar) from being used to bind an
attacker's workload key, the audience the workload requests must encode the
Ed25519 key being bound: :func:`expected_audience`. GCP and Kubernetes let a
workload choose its token audience, so this is enforced there. AWS instance
identity documents have no audience; the ``aws_iid`` attestor documents that it
proves instance identity only and should be paired with a network trust boundary
or short one-time windows.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import load_pem_x509_certificate

from .errors import AttestationDeniedError

GOOGLE_ISSUERS = frozenset({"https://accounts.google.com", "accounts.google.com"})
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"


def expected_audience(tenant_id: str, workload_keyhash: str) -> str:
    """The audience a workload must request in its node token, binding the token
    to this tenant and the exact workload key it will present. A token minted
    for one key cannot bind another."""
    return f"clayseal://{tenant_id}/attest/{workload_keyhash}"


@dataclass
class NodeAttestationResult:
    """Outcome of verifying node evidence: proven selectors plus the one-time id
    and expiry the issuance flow needs."""

    node_selectors: list[str]
    node_id: str
    jti: str
    expires_at: datetime


class NodeAttestor(Protocol):
    type: str

    def verify(
        self, evidence: dict, *, audience: str, max_ttl_seconds: int
    ) -> NodeAttestationResult: ...


# --------------------------------------------------------------------------- #
# GCP instance identity token
# --------------------------------------------------------------------------- #
class _JwksCache:
    """Small TTL cache of a JWKS document, so verification does not fetch on
    every call. ``fetch`` is injectable for tests and custom transports."""

    def __init__(self, url: str, fetch: Callable[[str], dict] | None = None, ttl: int = 3600):
        self._url = url
        self._fetch = fetch or _fetch_json
        self._ttl = ttl
        self._lock = threading.Lock()
        self._doc: dict | None = None
        self._at: float = 0.0

    def get(self) -> dict:
        with self._lock:
            now = time.time()
            if self._doc is None or now - self._at > self._ttl:
                self._doc = self._fetch(self._url)
                self._at = now
            return self._doc


def _fetch_json(url: str) -> dict:
    import httpx

    resp = httpx.get(url, timeout=10.0)
    resp.raise_for_status()
    return resp.json()


class GcpIitAttestor:
    """Verify a Google-signed instance identity token (``format=full``)."""

    type = "gcp_iit"

    def __init__(
        self,
        *,
        jwks_fetch: Callable[[str], dict] | None = None,
        issuers: frozenset[str] = GOOGLE_ISSUERS,
    ) -> None:
        self._jwks = _JwksCache(GOOGLE_JWKS_URL, jwks_fetch)
        self._issuers = issuers

    def verify(
        self, evidence: dict, *, audience: str, max_ttl_seconds: int
    ) -> NodeAttestationResult:
        token = evidence.get("token")
        if not token or not isinstance(token, str):
            raise AttestationDeniedError(
                "gcp_iit evidence must include the instance identity token.",
                suggestion=(
                    "Fetch it from the metadata server with format=full and the "
                    "audience Clay Seal expects (see docs)."
                ),
            )
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise AttestationDeniedError(
                "gcp_iit token is not a well-formed JWT.",
                suggestion="Present the raw token string from the metadata server.",
            ) from exc
        if header.get("alg") != "RS256":
            raise AttestationDeniedError(
                "gcp_iit token must be signed with RS256.",
                suggestion="Use the unmodified Google-issued token.",
            )
        key = _rsa_key_from_jwks(self._jwks.get(), header.get("kid"))
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                audience=audience,
                options={"require": ["iss", "aud", "exp", "iat", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AttestationDeniedError(
                "gcp_iit token has expired.",
                suggestion="Instance identity tokens are short-lived; fetch a fresh one.",
            ) from exc
        except jwt.InvalidAudienceError as exc:
            raise AttestationDeniedError(
                "gcp_iit token audience does not bind this tenant and workload key.",
                suggestion=(
                    "Request the token with the audience Clay Seal expects: "
                    "clayseal://<tenant>/attest/<workload-key-thumbprint>."
                ),
            ) from exc
        except jwt.InvalidTokenError as exc:
            raise AttestationDeniedError(
                f"gcp_iit token failed verification: {exc}",
                suggestion="Present an unmodified, current Google-issued token.",
            ) from exc

        if claims.get("iss") not in self._issuers:
            raise AttestationDeniedError(
                "gcp_iit token issuer is not Google.",
                suggestion="Only tokens issued by accounts.google.com are accepted.",
            )
        _enforce_max_ttl(claims["iat"], claims["exp"], max_ttl_seconds)

        ce = ((claims.get("google") or {}).get("compute_engine")) or {}
        project_id = ce.get("project_id")
        instance_id = ce.get("instance_id")
        zone = ce.get("zone")
        if not project_id or not instance_id:
            raise AttestationDeniedError(
                "gcp_iit token is missing compute-engine instance details.",
                suggestion="Request the token with format=full so project_id and instance_id are present.",
            )
        selectors = [f"gcp_iit:project-id:{project_id}", f"gcp_iit:instance-id:{instance_id}"]
        if zone:
            selectors.append(f"gcp_iit:zone:{zone}")
        if ce.get("instance_name"):
            selectors.append(f"gcp_iit:instance-name:{ce['instance_name']}")
        # Google ID tokens have no jti; the (sub, instance, iat) triple is unique
        # per issued token and the one-time table also keys on exp.
        jti = hashlib.sha256(
            f"gcp_iit:{claims['sub']}:{instance_id}:{claims['iat']}".encode()
        ).hexdigest()
        return NodeAttestationResult(
            node_selectors=selectors,
            node_id=str(instance_id),
            jti=jti,
            expires_at=_epoch_to_naive_utc(claims["exp"]),
        )


# --------------------------------------------------------------------------- #
# Kubernetes projected service-account token (PSAT), via TokenReview
# --------------------------------------------------------------------------- #
class TokenReviewer(Protocol):
    def review(self, token: str, audiences: list[str]) -> dict: ...


class HttpTokenReviewer:
    """Calls a cluster's TokenReview API. ``api_server`` is the Kubernetes API
    base URL, ``bearer_token`` the reviewer service account's token, ``ca_pem``
    the cluster CA (path or PEM). One reviewer per cluster."""

    def __init__(self, *, api_server: str, bearer_token: str, ca_pem: str | None = None):
        self._api = api_server.rstrip("/")
        self._token = bearer_token
        self._verify: Any = ca_pem if ca_pem else True

    def review(self, token: str, audiences: list[str]) -> dict:
        import httpx

        body = {
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenReview",
            "spec": {"token": token, "audiences": audiences},
        }
        resp = httpx.post(
            f"{self._api}/apis/authentication.k8s.io/v1/tokenreviews",
            headers={"Authorization": f"Bearer {self._token}"},
            json=body,
            verify=self._verify,
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json()


class K8sPsatAttestor:
    """Verify a projected service-account token through the cluster's
    TokenReview API and derive namespace / service-account / pod selectors."""

    type = "k8s_psat"

    def __init__(self, *, reviewer: TokenReviewer, cluster: str) -> None:
        self._reviewer = reviewer
        self._cluster = cluster

    def verify(
        self, evidence: dict, *, audience: str, max_ttl_seconds: int
    ) -> NodeAttestationResult:
        token = evidence.get("token")
        if not token or not isinstance(token, str):
            raise AttestationDeniedError(
                "k8s_psat evidence must include the projected service-account token.",
                suggestion="Mount a projected token whose audience is the value Clay Seal expects.",
            )
        try:
            review = self._reviewer.review(token, [audience])
        except Exception as exc:  # noqa: BLE001 - network/API failures
            raise AttestationDeniedError(
                "k8s_psat TokenReview call failed.",
                suggestion="Check the reviewer service account, API server URL, and cluster CA.",
            ) from exc

        status = review.get("status") or {}
        if not status.get("authenticated"):
            raise AttestationDeniedError(
                "k8s_psat token was rejected by the cluster (not authenticated).",
                suggestion="Present a current projected token with the expected audience.",
            )
        # The cluster confirms the audience matched what we asked TokenReview for;
        # our audience encodes the tenant + workload key, so binding holds.
        user = status.get("user") or {}
        username = str(user.get("username", ""))
        # system:serviceaccount:<namespace>:<serviceaccount>
        parts = username.split(":")
        if len(parts) != 4 or parts[0] != "system" or parts[1] != "serviceaccount":
            raise AttestationDeniedError(
                "k8s_psat token does not belong to a service account.",
                suggestion="Only projected service-account tokens are accepted.",
            )
        namespace, service_account = parts[2], parts[3]
        extra = user.get("extra") or {}
        pod_names = extra.get("authentication.kubernetes.io/pod-name") or []
        pod_uids = extra.get("authentication.kubernetes.io/pod-uid") or []
        selectors = [
            f"k8s_psat:cluster:{self._cluster}",
            f"k8s_psat:agent_ns:{namespace}",
            f"k8s_psat:agent_sa:{service_account}",
        ]
        if pod_names:
            selectors.append(f"k8s_psat:pod-name:{pod_names[0]}")
        node_id = pod_uids[0] if pod_uids else f"{namespace}/{service_account}"
        # Projected tokens are bound to the pod lifetime; the cluster enforces
        # expiry. Use the pod uid (or ns/sa) + a coarse time bucket as the
        # one-time key so the same token can't mint twice, without a jti claim.
        bucket = int(time.time()) // max_ttl_seconds
        jti = hashlib.sha256(f"k8s_psat:{node_id}:{bucket}".encode()).hexdigest()
        return NodeAttestationResult(
            node_selectors=selectors,
            node_id=str(node_id),
            jti=jti,
            expires_at=_epoch_to_naive_utc(int(time.time()) + max_ttl_seconds),
        )


# --------------------------------------------------------------------------- #
# AWS EC2 instance identity document
# --------------------------------------------------------------------------- #
class AwsIidAttestor:
    """Verify an EC2 instance identity document against AWS's regional public
    certificate (RSA-2048 / SHA-256). ``region_certs`` maps region -> PEM cert.

    The identity document has no audience or expiry, so it proves *which
    instance* is calling but not freshness. Pair it with a network trust
    boundary; the issuance flow's one-time table still prevents the same
    document minting twice."""

    type = "aws_iid"

    def __init__(self, *, region_certs: dict[str, str]) -> None:
        self._certs = region_certs

    def verify(
        self, evidence: dict, *, audience: str, max_ttl_seconds: int
    ) -> NodeAttestationResult:
        document = evidence.get("document")
        signature_b64 = evidence.get("signature")
        if not isinstance(document, str) or not isinstance(signature_b64, str):
            raise AttestationDeniedError(
                "aws_iid evidence must include the document and its RSA-2048 signature.",
                suggestion="Fetch both from the instance metadata service (IMDSv2).",
            )
        try:
            doc = json.loads(document)
        except ValueError as exc:
            raise AttestationDeniedError(
                "aws_iid document is not valid JSON.",
                suggestion="Present the unmodified instance identity document.",
            ) from exc
        region = doc.get("region")
        cert_pem = self._certs.get(region)
        if not cert_pem:
            raise AttestationDeniedError(
                f"No AWS public certificate configured for region {region!r}.",
                suggestion="Configure the AWS regional certificate for this instance's region.",
            )
        try:
            signature = base64.b64decode(signature_b64)
        except (binascii.Error, ValueError) as exc:
            raise AttestationDeniedError(
                "aws_iid signature is not valid base64.",
                suggestion="Present the RSA-2048 signature from the metadata service verbatim.",
            ) from exc
        public_key = load_pem_x509_certificate(cert_pem.encode()).public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise AttestationDeniedError(
                "Configured AWS certificate is not RSA.",
                suggestion="Use the RSA-2048 regional certificate AWS publishes.",
            )
        try:
            public_key.verify(
                signature,
                document.encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise AttestationDeniedError(
                "aws_iid signature does not match AWS's regional certificate.",
                suggestion="A forged or altered identity document is rejected.",
            ) from exc

        account = doc.get("accountId")
        instance_id = doc.get("instanceId")
        if not account or not instance_id:
            raise AttestationDeniedError(
                "aws_iid document is missing accountId or instanceId.",
                suggestion="Present the full instance identity document.",
            )
        selectors = [
            f"aws_iid:account:{account}",
            f"aws_iid:region:{region}",
            f"aws_iid:instance-id:{instance_id}",
        ]
        if doc.get("imageId"):
            selectors.append(f"aws_iid:image-id:{doc['imageId']}")
        jti = hashlib.sha256(
            f"aws_iid:{account}:{instance_id}:{doc.get('pendingTime', '')}".encode()
        ).hexdigest()
        return NodeAttestationResult(
            node_selectors=selectors,
            node_id=str(instance_id),
            jti=jti,
            expires_at=_epoch_to_naive_utc(int(time.time()) + max_ttl_seconds),
        )


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _rsa_key_from_jwks(jwks: dict, kid: str | None):
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not keys:
        raise AttestationDeniedError(
            "Could not load the provider's signing keys.",
            suggestion="The provider JWKS was empty or unreachable; retry.",
        )
    for jwk in keys:
        if kid is None or jwk.get("kid") == kid:
            try:
                return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
            except Exception:  # noqa: BLE001
                continue
    raise AttestationDeniedError(
        "No provider signing key matches the token's kid.",
        suggestion="The token references a key the provider has not published; retry with a fresh token.",
    )


def _enforce_max_ttl(iat: Any, exp: Any, max_ttl_seconds: int) -> None:
    if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float)):
        raise AttestationDeniedError(
            "Node token is missing valid iat/exp claims.",
            suggestion="Node evidence must be a short-lived token with iat and exp.",
        )
    if exp - iat > max_ttl_seconds:
        raise AttestationDeniedError(
            "Node token lifetime is too long.",
            suggestion=f"Keep node tokens at or below {max_ttl_seconds} seconds.",
        )


def _epoch_to_naive_utc(epoch: Any) -> datetime:
    return datetime.fromtimestamp(int(epoch), tz=UTC).replace(tzinfo=None)


def public_pem_from_key(key: rsa.RSAPublicKey) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


# --------------------------------------------------------------------------- #
# Process-level registry + issuance entry point
# --------------------------------------------------------------------------- #
# Cloud attestors are configured once for the identity service (which clouds it
# accepts and how to reach them), not per tenant — matching SPIRE, where node
# attestors are server plugins and per-tenant policy lives in registration
# entries. ``CLOUD_EVIDENCE_KIND`` tags a bundle so issuance can tell real cloud
# evidence from the static trust-anchor JWT.
CLOUD_EVIDENCE_KIND = "clayseal-node-evidence"

_REGISTRY: dict[str, NodeAttestor] = {}
_REGISTRY_LOCK = threading.Lock()


def register_cloud_attestor(attestor: NodeAttestor) -> None:
    with _REGISTRY_LOCK:
        _REGISTRY[attestor.type] = attestor


def get_cloud_attestor(attestor_type: str) -> NodeAttestor | None:
    return _REGISTRY.get(attestor_type)


def enabled_cloud_attestors() -> list[str]:
    return sorted(_REGISTRY)


def clear_cloud_attestors() -> None:
    """Test hook — reset the registry."""
    with _REGISTRY_LOCK:
        _REGISTRY.clear()


def parse_cloud_bundle(attestation_document: str) -> dict | None:
    """Return the cloud-evidence bundle if ``attestation_document`` is one, else
    ``None`` (so issuance falls back to the static trust-anchor JWT path)."""
    stripped = attestation_document.lstrip()
    if not stripped.startswith("{"):
        return None
    try:
        bundle = json.loads(stripped)
    except ValueError:
        return None
    if not isinstance(bundle, dict) or bundle.get("kind") != CLOUD_EVIDENCE_KIND:
        return None
    return bundle


def verify_cloud_node_attestation(
    bundle: dict, *, tenant_id: str, max_ttl_seconds: int
) -> tuple[NodeAttestationResult, str, dict]:
    """Verify a cloud-evidence bundle. Returns
    ``(result, workload_pubkey_pem, workload_block)``.

    The node token's audience must bind the tenant and the exact workload key
    being presented, so evidence captured elsewhere cannot be replayed to bind a
    different key.
    """
    from clayseal.workload_keys import canonical_public_pem, keyhash_for_pem

    attestor_type = bundle.get("type")
    attestor = get_cloud_attestor(str(attestor_type)) if attestor_type else None
    if attestor is None:
        raise AttestationDeniedError(
            f"Node attestor {attestor_type!r} is not enabled on this service.",
            suggestion=(
                "Enabled attestors: "
                + (", ".join(enabled_cloud_attestors()) or "(none)")
                + ". Configure the attestor, or use a registered static trust anchor."
            ),
        )
    workload_pubkey_pem = bundle.get("workload_pubkey_pem")
    if not workload_pubkey_pem or not isinstance(workload_pubkey_pem, str):
        raise AttestationDeniedError(
            "Cloud attestation evidence must include workload_pubkey_pem.",
            suggestion="Include the Ed25519 workload public key so the credential is bound to it.",
        )
    try:
        keyhash = keyhash_for_pem(canonical_public_pem(workload_pubkey_pem))
    except ValueError as exc:
        raise AttestationDeniedError(
            "workload_pubkey_pem must be an Ed25519 public key.",
            suggestion="Generate an ephemeral Ed25519 workload key and present its SPKI PEM.",
        ) from exc
    audience = expected_audience(tenant_id, keyhash)
    result = attestor.verify(
        bundle.get("evidence") or {},
        audience=audience,
        max_ttl_seconds=max_ttl_seconds,
    )
    return result, workload_pubkey_pem, (bundle.get("workload") or {})
