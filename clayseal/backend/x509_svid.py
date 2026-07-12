"""SPIFFE X.509-SVID issuance and trust bundles.

A JWT-SVID (``identity.py``) answers "which workload is acting" as a bearer-ish
signed token; an **X.509-SVID** is the certificate form of the same SPIFFE
identity, used for mTLS. The leaf certificate carries the workload's SPIFFE ID
as its single URI SAN and is signed by the tenant's CA.

Conformance (SPIFFE X509-SVID standard):

- exactly one URI SAN, the ``spiffe://`` ID, with a non-root path;
- KeyUsage (critical) sets ``digitalSignature`` and never ``keyCertSign`` /
  ``cRLSign``;
- ExtendedKeyUsage sets both ``serverAuth`` and ``clientAuth``;
- BasicConstraints ``CA=false``;
- signing (CA) certificates set ``CA=true`` with ``keyCertSign``.

The tenant CA is EC P-256; leaves carry whatever EC/RSA public key the workload
presents (its own private key never leaves the workload, so the cert is usable
for mTLS). The Ed25519 workload key used for JWT proof-of-possession is separate
— TLS stacks want EC/RSA, so the X.509-SVID uses a TLS-suitable key.
"""
from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import select
from sqlalchemy.orm import Session

from .errors import AttestationDeniedError
from .models import X509CaKey, new_id, utcnow
from .signing_keys import decrypt_private_pem, encrypt_private_pem

# Leaf lifetime is short; workloads re-fetch as they re-attest.
DEFAULT_SVID_TTL_SECONDS = 3600
CA_LIFETIME_DAYS = 365


# --------------------------------------------------------------------------- #
# Tenant CA
# --------------------------------------------------------------------------- #
def get_or_create_ca(db: Session, customer_id: str) -> X509CaKey:
    """Return the customer's active X.509 CA, creating one on first use."""
    ca = db.scalar(
        select(X509CaKey).where(
            X509CaKey.customer_id == customer_id, X509CaKey.status == "active"
        )
    )
    if ca is not None:
        return ca

    ca_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"Clay Seal CA {customer_id}")]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=CA_LIFETIME_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca = X509CaKey(
        kid=new_id(),
        customer_id=customer_id,
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        private_pem=encrypt_private_pem(
            ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode()
        ),
        algorithm="EC-P256",
    )
    db.add(ca)
    db.commit()
    db.refresh(ca)
    return ca


# --------------------------------------------------------------------------- #
# Leaf X.509-SVID
# --------------------------------------------------------------------------- #
def _require_non_root_spiffe_id(spiffe_id: str) -> None:
    """A leaf SVID's SPIFFE ID must be ``spiffe://<trust-domain>/<non-empty-path>``."""
    if not spiffe_id.startswith("spiffe://"):
        raise AttestationDeniedError(
            "SPIFFE ID must use the spiffe:// scheme.",
            suggestion="Use spiffe://<trust-domain>/customer/<id>/agent/<type>.",
        )
    remainder = spiffe_id[len("spiffe://") :]
    trust_domain, _, path = remainder.partition("/")
    if not trust_domain or not path.strip("/"):
        raise AttestationDeniedError(
            "SPIFFE ID must have a non-root path for an X.509-SVID.",
            suggestion="Use an identity like spiffe://<trust-domain>/customer/<id>/agent/<type>.",
        )


def _load_public_key(public_key_pem: str):
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode())
    except (ValueError, TypeError) as exc:
        raise AttestationDeniedError(
            "x509_public_key_pem is not a valid PEM public key.",
            suggestion="Present an EC (P-256/384) or RSA-2048+ SPKI public key for the X.509-SVID.",
        ) from exc
    if isinstance(key, ec.EllipticCurvePublicKey):
        return key
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048:
            raise AttestationDeniedError(
                "RSA X.509-SVID keys must be at least 2048 bits.",
                suggestion="Use RSA-2048+ or an EC P-256 key.",
            )
        return key
    raise AttestationDeniedError(
        "X.509-SVID keys must be EC or RSA (TLS stacks require them).",
        suggestion="Present an EC P-256 or RSA-2048 public key; keep Ed25519 for JWT proof-of-possession.",
    )


def _public_key_from_csr(csr_pem: str):
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except (ValueError, TypeError) as exc:
        raise AttestationDeniedError(
            "x509_csr_pem is not a valid PEM certificate signing request.",
            suggestion="Generate a CSR with the TLS private key held by the workload.",
        ) from exc
    if not csr.is_signature_valid:
        raise AttestationDeniedError(
            "x509_csr_pem signature is invalid.",
            suggestion="The CSR must be signed by the private key matching its public key.",
        )
    public_key = csr.public_key()
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return _load_public_key(public_pem)


def issue_x509_svid(
    db: Session,
    customer_id: str,
    *,
    spiffe_id: str,
    public_key_pem: str,
    ttl_seconds: int = DEFAULT_SVID_TTL_SECONDS,
) -> str:
    """Mint a leaf X.509-SVID for ``spiffe_id`` over the workload's public key.

    Returns the PEM chain: the leaf followed by the signing CA certificate.
    """
    _require_non_root_spiffe_id(spiffe_id)
    public_key = _load_public_key(public_key_pem)
    return _issue_x509_svid_for_public_key(
        db,
        customer_id,
        spiffe_id=spiffe_id,
        public_key=public_key,
        ttl_seconds=ttl_seconds,
    )


def issue_x509_svid_from_csr(
    db: Session,
    customer_id: str,
    *,
    spiffe_id: str,
    csr_pem: str,
    ttl_seconds: int = DEFAULT_SVID_TTL_SECONDS,
) -> str:
    """Mint a leaf X.509-SVID from a CSR signed by the workload TLS key."""
    _require_non_root_spiffe_id(spiffe_id)
    public_key = _public_key_from_csr(csr_pem)
    return _issue_x509_svid_for_public_key(
        db,
        customer_id,
        spiffe_id=spiffe_id,
        public_key=public_key,
        ttl_seconds=ttl_seconds,
    )


def _issue_x509_svid_for_public_key(
    db: Session,
    customer_id: str,
    *,
    spiffe_id: str,
    public_key,
    ttl_seconds: int,
) -> str:
    ca = get_or_create_ca(db, customer_id)
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
    ca_key = serialization.load_pem_private_key(
        decrypt_private_pem(ca.private_pem).encode(), password=None
    )

    now = datetime.now(UTC)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))  # SPIFFE ID lives in the SAN, not the subject
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(seconds=ttl_seconds))
        # Exactly one URI SAN = the SPIFFE ID; critical because the subject is empty.
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=True,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=isinstance(public_key, rsa.RSAPublicKey),
                data_encipherment=False,
                key_agreement=isinstance(public_key, ec.EllipticCurvePublicKey),
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
    return leaf_pem + ca.cert_pem


# --------------------------------------------------------------------------- #
# Trust bundle
# --------------------------------------------------------------------------- #
def x509_trust_bundle(db: Session, customer_id: str) -> dict:
    """Return the tenant's X.509 trust bundle in SPIFFE bundle (JWKS) form plus
    a PEM convenience: every active/retired CA cert, so a verifier can validate
    leaves issued by the current and recently-rotated CAs."""
    cutoff = utcnow() - timedelta(seconds=DEFAULT_SVID_TTL_SECONDS + 300)
    cas = list(
        db.scalars(
            select(X509CaKey)
            .where(X509CaKey.customer_id == customer_id)
            .order_by(X509CaKey.created_at.desc())
        ).all()
    )
    keys = []
    pem_parts = []
    for ca in cas:
        if ca.status != "active" and ca.retired_at is not None and ca.retired_at <= cutoff:
            continue
        cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
        der = cert.public_bytes(serialization.Encoding.DER)
        keys.append(
            {
                "kty": "EC" if ca.algorithm.startswith("EC") else "RSA",
                "use": "x509-svid",
                "x5c": [base64.b64encode(der).decode()],
            }
        )
        pem_parts.append(ca.cert_pem)
    return {"keys": keys, "spiffe_sequence": len(cas), "pem": "".join(pem_parts)}


def rotate_ca(db: Session, customer_id: str) -> X509CaKey:
    """Retire the active CA and create a new one; retired CAs stay in the bundle."""
    current = db.scalar(
        select(X509CaKey).where(
            X509CaKey.customer_id == customer_id, X509CaKey.status == "active"
        )
    )
    if current is not None:
        current.status = "retired"
        current.retired_at = utcnow()
        db.add(current)
        db.commit()
    return get_or_create_ca(db, customer_id)
