# syntax=docker/dockerfile:1
#
# Multi-stage build for the vulnpipe scanner image.
#
#   * builder -- installs vulnpipe and its dependencies into an isolated venv;
#   * runtime -- a slim image carrying only that venv plus the nmap binary the
#     network scanner drives. ZAP runs as its own service (see docker-compose.yml),
#     not in this image.
#
# Keeping the build tooling in the first stage keeps the runtime image small and
# reproducible: nothing but the resolved venv crosses the stage boundary.

# --------------------------------------------------------------------------- #
# Stage 1: build the virtualenv
# --------------------------------------------------------------------------- #
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore

# Self-contained venv so the runtime stage can copy a single directory.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /src
# Copy only what the install needs first, for better layer caching.
COPY pyproject.toml README.md ./
COPY vulnpipe ./vulnpipe
RUN pip install .

# --------------------------------------------------------------------------- #
# Stage 2: runtime
# --------------------------------------------------------------------------- #
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="vulnpipe" \
      org.opencontainers.image.description="Network + web vulnerability scanning pipeline (detection & reporting only)." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/"

# nmap: required by the network scanner. curl: used by the entrypoint to wait on
# the ZAP daemon. ca-certificates: TLS for NVD/EPSS enrichment lookups.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY configs ./configs
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

# Detection-and-report tool: run unprivileged. SYN scans need NET_RAW; without it
# nmap falls back to TCP connect scans, which work without elevated privileges.
RUN chmod +x /usr/local/bin/entrypoint.sh \
    && useradd --create-home --uid 1000 scanner \
    && mkdir -p /app/results \
    && chown -R scanner:scanner /app/results
USER scanner

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["--help"]
