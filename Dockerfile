# =============================================================================
# Stage 1 — wheel-builder
# 用标准镜像构建 wheel + 生成默认配置，不涉及任何 Chainguard 路径
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
# latest-dev 比 latest 多了 pip / apk，但 Python 版本、路径和 latest 完全一致。
# 在这里 pip install，输出的 site-packages 路径与 runtime 100% 匹配。
# =============================================================================
FROM cgr.dev/chainguard/python:latest-dev AS cg-builder

WORKDIR /build

# 复制 wheel
COPY --from=wheel-builder /build/dist/*.whl ./

# 安装到 /install prefix（root 可写），运行时以 nonroot 身份访问
USER root
RUN pip install --no-cache-dir --prefix=/install *.whl

# 探测 Chainguard Python 的真实 site-packages 路径
# 输出形如 /usr/lib/python3.13/site-packages，写到文件
RUN python -c \
    "import sysconfig; \
     sp = sysconfig.get_path('purelib'); \
     print('site-packages:', sp); \
     open('/install/SP_PATH', 'w').write(sp)"

# 验证 nanodns 可以被找到
RUN PYTHONPATH=$(cat /install/SP_PATH) python -m nanodns.cli --version


# =============================================================================
# Stage 3 — final  (cgr.dev/chainguard/python:latest — distroless)
#
# 无 shell、无 pip、无 apk。只有 /usr/bin/python。
# nonroot (uid=65532) 是默认且唯一的用户。
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

# 从 cg-builder 复制安装好的包
# /install/lib/pythonX.Y/site-packages → Chainguard 的实际 site-packages
# 因为 latest-dev 和 latest Python 版本完全一致，路径也一致
COPY --from=cg-builder /install/lib /usr/lib

# 默认配置
COPY --from=wheel-builder /build/nanodns.json /etc/nanodns.json

EXPOSE 53/udp

# 保持 Chainguard 默认 nonroot 用户
# 绑定 53 需要 docker run --cap-add NET_BIND_SERVICE

ENTRYPOINT ["/usr/bin/python", "-m", "nanodns.cli"]
CMD ["start", "--config", "/etc/nanodns.json"]