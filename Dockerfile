# ─── Stage 1: Builder ─────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml README.md ./
COPY nanodns/ ./nanodns/

RUN pip install --upgrade pip build \
 && python -m build --wheel --outdir /build/dist
 
RUN python -m pip install --no-cache-dir \
 --prefix=/install \
 /build/dist/*.whl


# ─── Stage 2: Chainguard Runtime ───────────────────────────────────
FROM cgr.dev/chainguard/python:latest

# OCI metadata args
ARG VERSION=0.1.0
ARG BUILD_DATE
ARG GIT_REVISION
ARG REPO_URL

LABEL org.opencontainers.image.title="NanoDNS" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_REVISION}" \
      org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.licenses="MIT"

# Copy installed packages
COPY --from=builder /install /usr/local

# Create config directory
WORKDIR /etc/nanodns
RUN mkdir -p /etc/nanodns

# Default config generation
RUN nanodns init /etc/nanodns/nanodns.json

EXPOSE 53/udp

USER root

ENTRYPOINT ["nanodns"]
CMD ["start","--config","/etc/nanodns/nanodns.json"]