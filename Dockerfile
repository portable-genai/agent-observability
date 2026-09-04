# agent-observability Agent Observability, Audit & FinOps — container image.
# Multi-stage: build a wheel, then install it (with the [gcp] extra) into a slim runtime.

# ---- builder ---------------------------------------------------------------- #
FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS builder

WORKDIR /build
RUN pip install --no-cache-dir build

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m build --wheel --outdir /dist

# ---- runtime ---------------------------------------------------------------- #
FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8085 \
    OBSERVABILITY_PROFILE=gcp

# Non-root runtime user.
RUN useradd --create-home --uid 10001 appuser
WORKDIR /app

# Install the GCP adapter dependencies from the committed lockfile (reproducible, no
# re-resolve; matches CI and pip-audit), then the wheel itself with --no-deps so the
# lock stays authoritative for every transitive pin.
COPY requirements-gcp.lock ./
COPY --from=builder /dist/*.whl /tmp/
# git is needed only while pip resolves the git+https commons pin (hex-service-kit);
# purge it in the same layer so the runtime image does not carry it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && pip install --no-cache-dir -r requirements-gcp.lock \
    && pip install --no-cache-dir --no-deps /tmp/*.whl \
    && apt-get purge -y git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/*.whl

# Settings file (env-interpolated at load time).
COPY config ./config

USER appuser
EXPOSE 8085

# Container-level liveness against the app's own /healthz (practice D4). Uses the runtime
# interpreter that is already present, so the slim image gains no curl/wget dependency and
# the healthcheck honours $PORT exactly like the CMD below.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8085')+'/healthz',timeout=2).read()" || exit 1

# Cloud Run injects $PORT; the shell form expands it at container start. Serve the ASGI
# app (module-level `app` in observability.api.app), not `python -m observability` (the
# Typer CLI, which prints help and never binds a port).
CMD exec uvicorn observability.api.app:app --host 0.0.0.0 --port ${PORT}
