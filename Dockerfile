# ─── Stage 1: Builder ────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml README.md ./
COPY nanodns/ ./nanodns/

RUN pip install --upgrade pip build \
 && python -m build --wheel --outdir /build/dist

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# OCI Image Spec annotations (populated at build time via --build-arg / --label)
ARG VERSION=0.1.0
ARG BUILD_DATE
ARG GIT_REVISION
ARG REPO_URL="https://github.com/iyuangang/nanodns"

LABEL org.opencontainers.image.title="nanodns" \
      org.opencontainers.image.description="Lightweight JSON-configurable DNS server for internal networks" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_REVISION}" \
      org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.url="${REPO_URL}" \
      org.opencontainers.image.documentation="${REPO_URL}/blob/main/USAGE.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="NanoDNS Contributors" \
      org.opencontainers.image.base.name="python:3.12-slim"

# Install wheel from builder stage
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Create non-root user
RUN useradd --system --uid 1001 --no-create-home nanodns

# Config directory
RUN mkdir -p /etc/nanodns && chown nanodns:nanodns /etc/nanodns

# Generate default config
RUN nanodns init /etc/nanodns/nanodns.json

WORKDIR /etc/nanodns

# DNS port
EXPOSE 53/udp

# Switch to non-root (Note: port 53 requires NET_BIND_SERVICE capability)
USER nanodns

VOLUME ["/etc/nanodns"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01', ('127.0.0.1',53)); s.recv(512); s.close()" || exit 1

ENTRYPOINT ["nanodns", "start", "--config", "/etc/nanodns/nanodns.json"]
