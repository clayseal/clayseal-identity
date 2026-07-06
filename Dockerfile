# Production image for the AgentAuth Identity Service.
#
# Layer note: this package depends on `agentauth-core`, which is published as a
# separate wheel. Make it resolvable at build time via a wheelhouse or a private
# index, e.g.:
#   docker build --build-arg PIP_EXTRA_INDEX_URL=https://pypi.example/simple .
# (pin the base image by digest in your registry/CI; we pin by tag here).
FROM python:3.12-slim AS base

# - PYTHONDONTWRITEBYTECODE: no .pyc clutter in the image
# - PYTHONUNBUFFERED: logs (our JSON lines) flush immediately for CloudWatch
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

ARG PIP_EXTRA_INDEX_URL=""
ENV PIP_EXTRA_INDEX_URL=${PIP_EXTRA_INDEX_URL}

WORKDIR /app

# Install dependencies first (better layer caching) then the package itself.
COPY pyproject.toml README.md ./
COPY agentauth ./agentauth
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini

# The service plus its psycopg[binary] + SQLAlchemy deps, the ASGI server, and
# boto3 (the [kms] extra) for the AWS KMS envelope-encryption provider that
# production selects via AGENTAUTH_SECRET_ENCRYPTION_PROVIDER=aws_kms.
RUN pip install --upgrade pip \
    && pip install ".[kms]" "uvicorn[standard]>=0.27" "psycopg[binary]>=3.1"

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000

# Liveness probe (readiness at /ready is checked by the orchestrator/ALB).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status==200 else 1)"

# Pre-deploy step (run separately, once per release, before rolling instances):
#   alembic upgrade head
# with AGENTAUTH_MANAGE_SCHEMA=alembic so the app never races on DDL.
CMD ["uvicorn", "agentauth.backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
