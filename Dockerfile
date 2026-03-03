# =============================================================================
# Stage 1 — builder
# 有完整工具链：构建 wheel、安装、生成默认配置、提取包文件
# =============================================================================
FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml README.md ./
COPY nanodns/ ./nanodns/

# 构建 wheel
RUN pip install --upgrade pip build \
 && python -m build --wheel --outdir /build/dist

# 安装到 builder 环境（有 pip 和 shell，完整可用）
RUN pip install --no-cache-dir /build/dist/*.whl

# 生成默认配置
RUN nanodns init /build/nanodns.json

# 提取 nanodns 包目录（不依赖硬编码的 pythonX.Y 路径）
RUN cp -r \
      "$(python -c 'import nanodns, os; print(os.path.dirname(nanodns.__file__))')" \
      /build/nanodns_pkg


# =============================================================================
# Stage 2 — final  (Chainguard distroless)
#
# 关键约束：
#   • 无 shell → 不能用 RUN，不能用 shell 形式的 ENTRYPOINT
#   • Python 位于 /usr/bin/python
#   • site-packages 位于 /usr/lib/python3.13/site-packages  ← Chainguard 当前版本
#   • 默认用户 nonroot (uid=65532)，不要改成 root
#
# 如果 Chainguard 升级 Python，在 CI 里用以下命令确认新路径：
#   docker run --rm cgr.dev/chainguard/python:latest \
#     /usr/bin/python -c "import site; print(site.getsitepackages()[0])"
# 然后更新下面 COPY 目标路径中的版本号即可。
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

# nanodns 包 → Chainguard site-packages
COPY --from=builder /build/nanodns_pkg \
                    /usr/lib/python3.13/site-packages/nanodns

# 默认配置
COPY --from=builder /build/nanodns.json /etc/nanodns.json

EXPOSE 53/udp

# 保持 Chainguard 默认的 nonroot 用户，不要 USER root
# 绑定 53 端口在 docker run / compose 里用 --cap-add NET_BIND_SERVICE

# 用 python -m 绕过 shebang 问题：
#   ✓ 不依赖 /usr/local/bin/nanodns 脚本是否存在
#   ✓ 不依赖 shebang 里的 Python 路径
#   ✓ distroless 无 shell 也能正常运行
ENTRYPOINT ["/usr/bin/python", "-m", "nanodns.cli"]
CMD ["start", "--config", "/etc/nanodns.json"]