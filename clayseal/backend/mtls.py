"""mTLS client certificate extraction and utilities.

Provides a Starlette middleware that extracts the client certificate from a
forwarded proxy header (the deployment terminates TLS at a proxy/load balancer
such as nginx/Envoy and forwards the client cert), plus a helper used by the
binding check in deps.py.
"""
from __future__ import annotations

import base64

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .config import get_settings


def cert_public_key_pem(cert_der: bytes) -> str:
    """Return the SPKI PEM public key extracted from a DER-encoded X.509 certificate."""
    cert = x509.load_der_x509_certificate(cert_der)
    return cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


class ClientCertMiddleware(BaseHTTPMiddleware):
    """Extract the mTLS client certificate and attach it to request.state.client_cert_der.

    Proxy mode: the client cert DER is base64-encoded in a configurable header
    (e.g. ``X-Client-Cert``) by a TLS-terminating proxy/load balancer. When no
    header is configured, no cert is attached and ``client_cert_der`` is ``None``.

    Settings are read per-request so tests can toggle env vars without restarting
    the app. This middleware only *extracts* the cert; binding/strict enforcement
    (returning 401) is performed by ``verify_mtls_binding`` in ``deps.py``.
    """

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()

        if not settings.mtls_enabled:
            request.state.client_cert_der = None
            return await call_next(request)

        cert_der: bytes | None = None

        if settings.mtls_client_cert_header:
            raw = request.headers.get(settings.mtls_client_cert_header)
            if raw:
                try:
                    cert_der = base64.b64decode(raw)
                except Exception:
                    return JSONResponse(
                        {
                            "error": {
                                "code": "mtls_invalid_cert_header",
                                "message": "Client certificate header is not valid base64.",
                            }
                        },
                        status_code=400,
                    )

        request.state.client_cert_der = cert_der
        return await call_next(request)
