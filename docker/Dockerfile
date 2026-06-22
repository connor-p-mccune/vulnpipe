# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

# Nmap is required by the network scanner stage. ZAP runs as its own service.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install the package first (better layer caching).
COPY pyproject.toml README.md ./
COPY vulnpipe ./vulnpipe
RUN pip install --no-cache-dir .

COPY configs ./configs
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Detection-and-report tool: run unprivileged. Note: SYN scans need NET_RAW;
# without it, Nmap falls back to TCP connect scans.
RUN useradd --create-home --uid 1000 scanner
USER scanner

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["--help"]
