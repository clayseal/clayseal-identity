"""FastAPI application factory + global error handling."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from . import __version__
from .config import get_settings
from .db import SessionLocal, init_db
from .errors import AgentAuthError
from .observability import RequestLoggingMiddleware, configure_logging, get_logger
from .rate_limit import RateLimitMiddleware
from .routers import federation, identity
from .secret_encryption import (
    encryption_enabled,
    secret_encryption_required,
)
from .production import validate_production_startup


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown. Validate config, then bring the schema up (dev/SQLite).

    Replaces the deprecated ``@app.on_event("startup")`` hook so DB init and
    encryption/DB-config validation keep working across FastAPI upgrades.
    """
    settings = get_settings()
    configure_logging(settings)
    # Fail fast on unsafe production config before serving any traffic.
    validate_production_startup(settings)
    init_db()
    get_logger().info(
        "startup complete",
        extra={
            "event": "startup",
            "env": settings.env,
            "manage_schema": settings.manage_schema,
            "rate_limit_enabled": settings.rate_limit_enabled,
        },
    )
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Clay Seal",
        version=__version__,
        description=(
            "Attested identity and verifiable execution receipts for AI agents "
            "-- attested agent identity: JWT-SVID credentials and Biscuit capabilities."
        ),
        lifespan=lifespan,
    )

    # Allow the browser dashboard (a separate origin) to call the API with the
    # X-API-Key header. Origins are configurable via AGENTAUTH_CORS_ORIGINS.
    origins = get_settings().cors_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Content-Disposition"],
    )
    # ClientCertMiddleware added here (runs before auth deps) so
    # request.state.client_cert_der is populated before any auth dependency fires.
    # It is always registered; it self-disables per-request when mtls_enabled=False.
    from .mtls import ClientCertMiddleware
    app.add_middleware(ClientCertMiddleware)
    # Rate limiting (self-disables when disabled). Added after ClientCert so it is
    # outer to it, and inner to request logging so 429s are still logged.
    app.add_middleware(RateLimitMiddleware)
    # Request logging added last => outermost => sees the final status of every
    # request (including rate-limited/auth-failed ones) and sets X-Request-ID.
    app.add_middleware(RequestLoggingMiddleware)

    @app.exception_handler(AgentAuthError)
    async def _agentauth_error_handler(_request: Request, exc: AgentAuthError) -> JSONResponse:
        return JSONResponse(status_code=exc.http_status, content=exc.to_dict())

    @app.get("/health", tags=["meta"])
    def health() -> dict:
        """Liveness: the process is up. Cheap; no dependency checks."""
        settings = get_settings()
        return {
            "status": "ok",
            "version": __version__,
            "secret_encryption": {
                "enabled": encryption_enabled(),
                "required": secret_encryption_required(settings.database_url),
            },
        }

    @app.get("/ready", tags=["meta"])
    def ready() -> JSONResponse:
        """Readiness: can we serve traffic? Verifies DB connectivity (SELECT 1)."""
        try:
            with SessionLocal() as db:
                db.execute(text("SELECT 1"))
        except Exception as exc:  # noqa: BLE001 - report not-ready, don't crash
            get_logger().error(
                "readiness check failed",
                extra={"event": "readiness", "error_type": type(exc).__name__},
            )
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "checks": {"database": "error"}},
            )
        return JSONResponse(
            status_code=200,
            content={"status": "ready", "checks": {"database": "ok"}},
        )

    app.include_router(identity.router)
    app.include_router(federation.router)
    return app


app = create_app()
