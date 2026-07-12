"""Client-side X.509-SVID helpers: generate a TLS keypair and materialize the
SVID for mTLS.

A workload asks for an X.509-SVID with ``auth.identify(..., request_x509=True)``.
The SDK generates an EC P-256 keypair locally (the private key never leaves the
process), sends a CSR signed by that key, and stores the returned certificate chain. Use
:func:`write_mtls_files` or :func:`mtls_context` to turn the SVID into something
a TLS stack can use.
"""
from __future__ import annotations

import os
import ssl
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def generate_ec_keypair() -> tuple[str, str]:
    """Return a fresh EC P-256 ``(private_pem, public_pem)`` for an X.509-SVID."""
    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return private_pem, public_pem


def generate_ec_keypair_and_csr() -> tuple[str, str]:
    """Return a fresh EC P-256 ``(private_pem, csr_pem)`` for an X.509-SVID."""
    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "clayseal-workload")]))
        .sign(key, hashes.SHA256())
    )
    return private_pem, csr.public_bytes(serialization.Encoding.PEM).decode()


def write_mtls_files(
    *, svid_chain_pem: str, private_key_pem: str, trust_bundle_pem: str, directory: str
) -> dict[str, str]:
    """Write the SVID chain, private key, and trust bundle to a directory and
    return their paths (``svid``, ``key``, ``bundle``). Files are written 0600."""
    paths = {
        "svid": os.path.join(directory, "svid.pem"),
        "key": os.path.join(directory, "svid.key"),
        "bundle": os.path.join(directory, "bundle.pem"),
    }
    for path, content in (
        (paths["svid"], svid_chain_pem),
        (paths["key"], private_key_pem),
        (paths["bundle"], trust_bundle_pem),
    ):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
    return paths


def mtls_context(
    *,
    svid_chain_pem: str,
    private_key_pem: str,
    trust_bundle_pem: str,
    purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
) -> ssl.SSLContext:
    """Build an :class:`ssl.SSLContext` that presents this X.509-SVID and trusts
    peers in the tenant bundle. ``purpose`` is ``SERVER_AUTH`` for a client
    connecting out, or ``CLIENT_AUTH`` for a server accepting connections.

    SPIFFE identifies peers by their URI SAN, not hostname, so hostname checking
    is disabled; authorize the peer by reading its SPIFFE ID from the presented
    certificate.
    """
    tmp = tempfile.mkdtemp(prefix="clayseal-mtls-")
    paths = write_mtls_files(
        svid_chain_pem=svid_chain_pem,
        private_key_pem=private_key_pem,
        trust_bundle_pem=trust_bundle_pem,
        directory=tmp,
    )
    ctx = ssl.SSLContext(
        ssl.PROTOCOL_TLS_CLIENT if purpose is ssl.Purpose.SERVER_AUTH else ssl.PROTOCOL_TLS_SERVER
    )
    ctx.load_cert_chain(certfile=paths["svid"], keyfile=paths["key"])
    ctx.load_verify_locations(cafile=paths["bundle"])
    ctx.verify_mode = ssl.CERT_REQUIRED
    if purpose is ssl.Purpose.SERVER_AUTH:
        ctx.check_hostname = False  # SPIFFE authorizes by URI SAN, not hostname
    return ctx
