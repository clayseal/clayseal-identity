"""Runtime configuration, sourced from environment variables with sane defaults.

Everything is overridable via env so tests can point at temp files and a
deployment can point at real infrastructure without code changes.
"""
from __future__ import annotations

import os
from functools import lru_cache


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    def __init__(self) -> None:
        # Deployment environment. ``production`` turns on the strict guards
        # (no SQLite, secret encryption required, rate limiting on by default).
        self.env: str = os.getenv("CLAYSEAL_ENV", "development").strip().lower()

        self.database_url: str = os.getenv(
            "CLAYSEAL_DATABASE_URL", "sqlite:///./agents.db"
        )

        # --- SQLAlchemy connection-pool tuning (ignored for SQLite) --------- #
        # pool_pre_ping detects and recycles stale connections (RDS failovers,
        # idle-timeout kills) before they surface as errors; pool_recycle caps
        # a connection's lifetime. All env-overridable.
        self.db_pool_size: int = int(os.getenv("CLAYSEAL_DB_POOL_SIZE", "5"))
        self.db_max_overflow: int = int(os.getenv("CLAYSEAL_DB_MAX_OVERFLOW", "10"))
        self.db_pool_recycle: int = int(os.getenv("CLAYSEAL_DB_POOL_RECYCLE", "1800"))
        self.db_pool_timeout: int = int(os.getenv("CLAYSEAL_DB_POOL_TIMEOUT", "30"))
        self.db_pool_pre_ping: bool = _env_flag("CLAYSEAL_DB_POOL_PRE_PING", True)

        # Schema management strategy: "alembic" means DDL is applied out-of-band
        # by `alembic upgrade head` and the app never creates/alters tables at
        # startup (recommended for prod/Postgres). Anything else keeps the
        # dev-friendly create_all + additive column sync.
        self.manage_schema: str = os.getenv("CLAYSEAL_MANAGE_SCHEMA", "auto").strip().lower()

        # Admin bootstrap key gating tenant creation. When set, POST /v1/customers
        # requires a matching X-Admin-Key header. Unset => open in dev, refused
        # in production (fail closed).
        self.admin_api_key: str | None = os.getenv("CLAYSEAL_ADMIN_API_KEY") or None

        # --- Rate limiting (in-memory; AWS WAF/gateway is authoritative behind
        # multiple instances) ------------------------------------------------ #
        self.rate_limit_enabled: bool = _env_flag(
            "CLAYSEAL_RATE_LIMIT_ENABLED", self.env == "production"
        )
        self.rate_limit_window_seconds: int = int(
            os.getenv("CLAYSEAL_RATE_LIMIT_WINDOW", "60")
        )
        # Requests per window for ordinary reads (per client IP and per API key).
        self.rate_limit_default: int = int(os.getenv("CLAYSEAL_RATE_LIMIT_DEFAULT", "600"))
        # Stricter budget for mutating / key-generating endpoints.
        self.rate_limit_mutating: int = int(os.getenv("CLAYSEAL_RATE_LIMIT_MUTATING", "60"))
        # When behind a trusted ALB/API gateway that strips untrusted
        # X-Forwarded-For input, use the left-most forwarded client IP. This is
        # opt-in: if the app is exposed directly, trusting this header lets an
        # attacker choose a fresh IP on every request and sidestep per-IP rate
        # limits.
        self.trust_proxy_headers: bool = _env_flag(
            "CLAYSEAL_TRUST_PROXY_HEADERS", False
        )

        # --- Caches (bounded TTL, in-memory) -------------------------------- #
        # Verified API-key cache: repeat authenticated calls skip PBKDF2.
        self.api_key_cache_ttl_seconds: int = int(
            os.getenv("CLAYSEAL_API_KEY_CACHE_TTL", "300")
        )
        self.api_key_cache_max_size: int = int(
            os.getenv("CLAYSEAL_API_KEY_CACHE_MAX", "2048")
        )
        # Decrypted signing-material cache: skip per-issuance KMS/AES decrypt.
        self.signing_key_cache_ttl_seconds: int = int(
            os.getenv("CLAYSEAL_SIGNING_KEY_CACHE_TTL", "300")
        )
        self.signing_key_cache_max_size: int = int(
            os.getenv("CLAYSEAL_SIGNING_KEY_CACHE_MAX", "1024")
        )
        # The identity event log (issuance / revocation / rotation) is now a
        # hash-chained table in the database above (see backend/audit.py), not a
        # flat file, so there is no separate audit-log path to configure.

        # TTL bounds (seconds). Spec: minimum 5 minutes, maximum 24 hours.
        self.min_ttl_seconds: int = int(os.getenv("CLAYSEAL_MIN_TTL", str(5 * 60)))
        self.max_ttl_seconds: int = int(os.getenv("CLAYSEAL_MAX_TTL", str(24 * 60 * 60)))
        self.default_ttl_seconds: int = int(os.getenv("CLAYSEAL_DEFAULT_TTL", str(60 * 60)))
        # Signed node/workload attestation evidence should be very short-lived:
        # it is consumed once, but a leaked unused document should not remain
        # useful for a long window.
        self.attestation_max_ttl_seconds: int = int(
            os.getenv("CLAYSEAL_ATTESTATION_MAX_TTL", "300")
        )

        # SPIFFE trust domain. Every issued JWT-SVID's subject is a SPIFFE ID
        # under this domain (spiffe://{trust_domain}/customer/{id}/agent/{type}),
        # and it doubles as the JWT issuer (`iss`).
        self.trust_domain: str = os.getenv("CLAYSEAL_TRUST_DOMAIN", "clayseal.io")
        self.jwt_issuer: str = os.getenv("CLAYSEAL_ISSUER", self.trust_domain)
        self.jwt_algorithm: str = "RS256"
        # Minimum key size for the prototype node-attestation RSA trust anchor.
        # ClaySeal-issued credentials use Ed25519.
        self.rsa_key_size: int = int(os.getenv("CLAYSEAL_RSA_KEY_SIZE", "2048"))

        # 32-byte hex key for AES-GCM (local) or KMS envelope encryption at rest.
        self.signing_key_encryption_key: str | None = os.getenv(
            "CLAYSEAL_SIGNING_KEY_ENCRYPTION_KEY"
        )
        self.secret_encryption_provider: str = os.getenv(
            "CLAYSEAL_SECRET_ENCRYPTION_PROVIDER", "local"
        )
        self.aws_kms_key_id: str | None = os.getenv("CLAYSEAL_AWS_KMS_KEY_ID")
        self.gcp_kms_key_name: str | None = os.getenv("CLAYSEAL_GCP_KMS_KEY_NAME")

        # CORS: comma-separated allowed origins for browser clients.
        # Defaults to the Vite dev server. Use "*" to allow any origin.
        self.cors_origins: list[str] = [
            o.strip()
            for o in os.getenv(
                "CLAYSEAL_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
            ).split(",")
            if o.strip()
        ]
        self.http_allowed_hosts: list[str] = [
            h.strip()
            for h in os.getenv("CLAYSEAL_HTTP_ALLOWED_HOSTS", "").split(",")
            if h.strip()
        ]

        # mTLS transport settings — paths to SPIRE-rotated X.509 SVID material in prod.
        self.mtls_enabled: bool = _env_flag("CLAYSEAL_MTLS_ENABLED", False)
        self.tls_cert_file: str | None = os.getenv("CLAYSEAL_TLS_CERT_FILE")
        self.tls_key_file: str | None = os.getenv("CLAYSEAL_TLS_KEY_FILE")
        self.tls_ca_bundle: str | None = os.getenv("CLAYSEAL_TLS_CA_BUNDLE")
        # When True, missing/mismatched cert → 401; False = extract if present, skip if absent.
        self.mtls_strict: bool = _env_flag("CLAYSEAL_MTLS_STRICT", True)
        # Proxy mode: DER cert forwarded as base64 in this header (e.g. by nginx/Envoy).
        # Also used by tests to inject certs without a real TLS handshake.
        self.mtls_client_cert_header: str | None = os.getenv("CLAYSEAL_MTLS_CLIENT_CERT_HEADER")

        # Structured logging verbosity.
        self.log_level: str = os.getenv("CLAYSEAL_LOG_LEVEL", "INFO").strip().upper()

    @property
    def is_production(self) -> bool:
        return self.env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
