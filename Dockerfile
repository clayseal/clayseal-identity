# Production image for the ClaySeal Identity Service.
#
# All dependencies resolve from public PyPI (PIP_EXTRA_INDEX_URL stays available
# for mirrors). Pin the base image by digest in your registry/CI; we pin by tag
# here.
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
COPY clayseal ./clayseal
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini

# The [server] extra carries the FastAPI service, ASGI server, SQLAlchemy,
# psycopg, and alembic; [kms] adds boto3 for the AWS KMS envelope-encryption
# provider that production selects via CLAYSEAL_SECRET_ENCRYPTION_PROVIDER=aws_kms.
RUN pip install --upgrade pip \
    && pip install ".[server,kms]"

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000

# Liveness probe (readiness at /ready is checked by the orchestrator/ALB).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status==200 else 1)"

# Pre-deploy step (run separately, once per release, before rolling instances):
#   alembic upgrade head
# with CLAYSEAL_MANAGE_SCHEMA=alembic so the app never races on DDL.
CMD ["uvicorn", "clayseal.backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
