FROM ghcr.io/astral-sh/uv:0.11.33 AS uv
FROM python:3.12-slim-bookworm AS builder
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
COPY . .
RUN uv sync --locked --no-dev --no-editable

# Separate trust boundary: the worker has no direct external network route.
FROM debian:bookworm-slim AS github-egress
RUN apt-get update \
 && apt-get install -y --no-install-recommends squid ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY deploy/squid.conf /etc/squid/squid.conf
USER proxy:proxy
CMD ["squid", "-N", "-f", "/etc/squid/squid.conf"]

FROM python:3.12-slim-bookworm AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates libseccomp2 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 1000 --create-home quanta \
 && mkdir -p /var/lib/quanta/artifacts /var/lib/quanta/scratch \
 && chown -R 1000:1000 /var/lib/quanta
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    QUANTA_DB=/var/lib/quanta/quanta.db \
    QUANTA_ARTIFACT_ROOT=/var/lib/quanta/artifacts \
    QUANTA_SCRATCH_ROOT=/var/lib/quanta/scratch
USER 1000:1000
WORKDIR /var/lib/quanta
EXPOSE 8000
CMD ["quanta", "serve", "--host", "0.0.0.0", "--port", "8000"]
