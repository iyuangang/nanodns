# ─── Stage 1: Builder ─────────────────────────────────────────────
# 用标准 python:3.12-slim 构建 wheel，拥有完整工具链
FROM python:3.12-slim AS builder

WORKDIR /build

# 先复制依赖声明，充分利用 layer cache
COPY pyproject.toml README.md ./
COPY nanodns/ ./nanodns/

# 构建 wheel
RUN pip install --upgrade pip build \
 && python -m build --wheel --outdir /build/dist

# 把 wheel 安装到独立前缀 /install，便于干净复制到 runtime 镜像
RUN pip install --no-cache-dir \
      --prefix=/install \
      --force-reinstall \
      /build/dist/*.whl

# 生成默认配置
# --prefix 安装的包不在默认 sys.path 里，需要显式设置 PYTHONPATH
RUN PYTHONPATH=/install/lib/$(python -c "import sys; print(f'python{sys.version_info.major}.{sys.version_info.minor}')")/site-packages \
    /install/bin/nanodns init /build/nanodns.json


# ─── Stage 2: Chainguard distroless runtime ───────────────────────
# cgr.dev/chainguard/python:latest 是 distroless 镜像：
#   • 无 shell（无法执行 RUN 指令）
#   • Python 在 /usr/bin/python
#   • site-packages 在 /usr/lib/python3.x/site-packages
#   • 默认以非 root 的 nonroot(65532) 用户运行
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

# ── 复制 site-packages ──────────────────────────────────────────────
# Chainguard python:latest 的 Python 版本可能是 3.12，路径如下。
# 若升级镜像 Python 版本，修改这里的 3.12 即可。
COPY --from=builder /install/lib/python3.12/site-packages \
                    /usr/lib/python3.12/site-packages

# ── 复制可执行脚本 ──────────────────────────────────────────────────
# Chainguard 的 PATH 包含 /usr/local/bin，把入口脚本放在这里
COPY --from=builder /install/bin/nanodns /usr/local/bin/nanodns

# ── 复制默认配置 ────────────────────────────────────────────────────
COPY --from=builder /build/nanodns.json /etc/nanodns.json

# DNS 端口
EXPOSE 53/udp

# Chainguard python:latest 默认已经是非 root 的 nonroot 用户(uid=65532)
# 绑定 53 端口需要在 docker run / compose 时加 --cap-add NET_BIND_SERVICE
# 或者在 compose 里配置 cap_add: [NET_BIND_SERVICE]
# 不要在这里 USER root —— 那是安全风险

ENTRYPOINT ["nanodns"]
CMD ["start", "--config", "/etc/nanodns.json"]
