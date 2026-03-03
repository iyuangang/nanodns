# =============================================================================
# Stage 1 — wheel-builder
# 用标准镜像构建 wheel + 生成默认配置
# =============================================================================
FROM python:3.12-slim AS wheel-builder

WORKDIR /build

COPY pyproject.toml README.md ./
COPY nanodns/ ./nanodns/

RUN pip install --upgrade pip build \
 && python -m build --wheel --outdir /build/dist \
 && pip install --no-cache-dir /build/dist/*.whl \
 && nanodns init /build/nanodns.json


# =============================================================================
# Stage 2 — cg-builder  (cgr.dev/chainguard/python:latest-dev)
#
# 用与 runtime 完全相同的 Python 解释器来安装包。
# 关键：用 --target 直接装进 sysconfig 探测到的 site-packages，
# 而不是用 --prefix（--prefix 会用 pip 自身的 Python 版本决定子目录名）。
# =============================================================================
FROM cgr.dev/chainguard/python:latest-dev AS cg-builder

WORKDIR /build

COPY --from=wheel-builder /build/dist/*.whl ./

USER root

# 1. 探测本镜像 Python 的 site-packages 绝对路径（如 /usr/lib/python3.14/site-packages）
# 2. 用 --target 直接装进去，路径与 runtime 镜像 100% 一致
# 3. 原地验证：python -m nanodns.cli --version 必须成功，否则构建失败
RUN SP=$(python -c "import sysconfig; print(sysconfig.get_path('purelib'))") \
 && echo "Installing into: ${SP}" \
 && pip install --no-cache-dir --target="${SP}" *.whl \
 && python -m nanodns.cli --version


# =============================================================================
# Stage 3 — final  (cgr.dev/chainguard/python:latest — distroless)
# =============================================================================
FROM cgr.dev/chainguard/python:latest

ARG VERSION=0.1.0
ARG BUILD_DATE
ARG GIT_REVISION
ARG REPO_URL

LABEL org.opencontainers.image.title="NanoDNS" \
      org.opencontainers.image.description="Lightweight JSON-configurable DNS server" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_REVISION}" \
      org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.licenses="MIT"

# cg-builder 已经把包装进了正确的 site-packages 路径
# 直接把整个 /usr/lib 覆盖过来（只多了 nanodns 包，不影响其他内容）
COPY --from=cg-builder /usr/lib /usr/lib

# 默认配置
COPY --from=wheel-builder /build/nanodns.json /etc/nanodns.json

EXPOSE 53/udp

# 保持 Chainguard 默认 nonroot 用户 (uid=65532)
# 绑定 53 端口需要 --cap-add NET_BIND_SERVICE

ENTRYPOINT ["/usr/bin/python", "-m", "nanodns.cli"]
CMD ["start", "--config", "/etc/nanodns.json"]