"""SPIFFE X.509-SVID issuance and trust bundles.

Verifies the minted leaf is a spec-conformant SPIFFE X.509-SVID (single URI SAN
= the SPIFFE ID, correct key usages, CA=false) and that it chains to the tenant
CA published in the trust bundle — using standard ``cryptography`` verification,
not our own code, so a real SPIFFE consumer would accept it.
"""
from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from clayseal.backend.db import SessionLocal
from clayseal.backend.errors import AttestationDeniedError
from clayseal.backend.x509_svid import (
    get_or_create_ca,
    issue_x509_svid,
    rotate_ca,
    x509_trust_bundle,
)

SPIFFE_ID = "spiffe://clayseal.io/customer/acme/agent/researcher"


def _ec_public_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def _leaf(chain_pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(chain_pem.encode())


def _issue(db, customer_id, spiffe_id=SPIFFE_ID, public_pem=None):
    return issue_x509_svid(
        db,
        customer_id,
        spiffe_id=spiffe_id,
        public_key_pem=public_pem or _ec_public_pem(),
    )


def test_leaf_has_single_uri_san_equal_to_spiffe_id(customer):
    with SessionLocal() as db:
        chain = _issue(db, customer["customer_id"])
    san = _leaf(chain).extensions.get_extension_for_class(x509.SubjectAlternativeName)
    uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
    assert uris == [SPIFFE_ID]
    assert san.critical is True  # subject is empty, so SAN must be critical


def test_leaf_key_usage_is_spiffe_conformant(customer):
    with SessionLocal() as db:
        chain = _issue(db, customer["customer_id"])
    leaf = _leaf(chain)
    ku = leaf.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.critical is True
    assert ku.value.digital_signature is True
    assert ku.value.key_cert_sign is False
    assert ku.value.crl_sign is False
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False


def test_leaf_chains_to_the_tenant_ca(customer):
    with SessionLocal() as db:
        chain = _issue(db, customer["customer_id"])
        ca = get_or_create_ca(db, customer["customer_id"])
    leaf = _leaf(chain)
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
    # Standard signature verification: the CA public key verifies the leaf.
    ca_pub = ca_cert.public_key()
    ca_pub.verify(
        leaf.signature,
        leaf.tbs_certificate_bytes,
        ec.ECDSA(leaf.signature_hash_algorithm),
    )
    assert leaf.issuer == ca_cert.subject


def test_ca_cert_is_a_ca(customer):
    with SessionLocal() as db:
        ca = get_or_create_ca(db, customer["customer_id"])
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
    bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    ku = ca_cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign is True


def test_trust_bundle_contains_the_ca_and_validates_the_leaf(customer):
    with SessionLocal() as db:
        chain = _issue(db, customer["customer_id"])
        bundle = x509_trust_bundle(db, customer["customer_id"])
    assert bundle["keys"] and bundle["keys"][0]["use"] == "x509-svid"
    # The PEM bundle parses to the CA that signed the leaf.
    ca_cert = x509.load_pem_x509_certificate(bundle["pem"].encode())
    leaf = _leaf(chain)
    ca_cert.public_key().verify(
        leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm)
    )


def test_rsa_workload_key_is_accepted(customer):
    rsa_pub = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    with SessionLocal() as db:
        chain = _issue(db, customer["customer_id"], public_pem=rsa_pub)
    assert isinstance(_leaf(chain).public_key(), rsa.RSAPublicKey)


def test_ed25519_workload_key_is_rejected(customer):
    ed_pub = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    with SessionLocal() as db:
        with pytest.raises(AttestationDeniedError, match="EC or RSA"):
            _issue(db, customer["customer_id"], public_pem=ed_pub)


def test_root_path_spiffe_id_is_rejected(customer):
    with SessionLocal() as db:
        with pytest.raises(AttestationDeniedError, match="non-root path"):
            _issue(db, customer["customer_id"], spiffe_id="spiffe://clayseal.io")


def test_leaf_from_one_tenant_does_not_verify_against_another(customer, client):
    other = client.post("/v1/customers", json={"name": "Other Co"}).json()
    with SessionLocal() as db:
        chain = _issue(db, customer["customer_id"])
        other_ca = get_or_create_ca(db, other["customer_id"])
    leaf = _leaf(chain)
    other_pub = x509.load_pem_x509_certificate(other_ca.cert_pem.encode()).public_key()
    with pytest.raises(InvalidSignature):
        other_pub.verify(
            leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm)
        )


def test_rotation_keeps_old_ca_in_bundle(customer):
    with SessionLocal() as db:
        first = _issue(db, customer["customer_id"])
        first_ca_kid = get_or_create_ca(db, customer["customer_id"]).kid
        rotate_ca(db, customer["customer_id"])
        second_ca_kid = get_or_create_ca(db, customer["customer_id"]).kid
        bundle = x509_trust_bundle(db, customer["customer_id"])
    assert first_ca_kid != second_ca_kid
    # Both CAs are present so leaves from before the rotation still validate.
    assert len(bundle["keys"]) >= 2
    assert first  # the pre-rotation leaf was issued


def test_svid_completes_a_real_mtls_handshake(customer, tmp_path):
    """The leaf + its private key + the trust bundle establish a real TLS
    connection, and the peer's SPIFFE ID is recovered from the cert — proving
    the SVID is usable for mTLS, not just well-formed."""
    import socket
    import ssl
    import threading

    # Workload generates its own EC key; only the public half is sent for signing.
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    with SessionLocal() as db:
        chain = _issue(db, customer["customer_id"], public_pem=pub_pem)
        bundle = x509_trust_bundle(db, customer["customer_id"])

    cert_file = tmp_path / "svid.pem"
    key_file = tmp_path / "svid.key"
    ca_file = tmp_path / "bundle.pem"
    cert_file.write_text(chain)
    key_file.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ca_file.write_text(bundle["pem"])

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    server_ctx.load_verify_locations(cafile=str(ca_file))
    server_ctx.verify_mode = ssl.CERT_REQUIRED  # require the client's SVID too

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_verify_locations(cafile=str(ca_file))
    client_ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    client_ctx.check_hostname = False  # SPIFFE identifies by URI SAN, not hostname

    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]
    peer_spiffe: dict = {}

    def serve():
        conn, _ = lsock.accept()
        with server_ctx.wrap_socket(conn, server_side=True) as tls:
            der = tls.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(der)
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            peer_spiffe["id"] = san.value.get_values_for_type(x509.UniformResourceIdentifier)[0]
            tls.recv(16)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    with socket.create_connection(("127.0.0.1", port)) as raw:
        with client_ctx.wrap_socket(raw, server_hostname="ignored") as tls:
            tls.send(b"hello")
    t.join(timeout=5)
    lsock.close()

    # The mutually-authenticated peer presented our SPIFFE ID.
    assert peer_spiffe["id"] == SPIFFE_ID
