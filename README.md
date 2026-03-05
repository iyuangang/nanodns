# NanoDNS

> A lightweight, zero-dependency DNS server for internal networks — one JSON file, no moving parts, with built-in multi-node HA.

[![PyPI version](https://img.shields.io/pypi/v/nanodns.svg)](https://pypi.org/project/nanodns/)
[![Python](https://img.shields.io/pypi/pyversions/nanodns.svg)](https://pypi.org/project/nanodns/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/iyuangang/nanodns/actions/workflows/release.yml/badge.svg)](https://github.com/iyuangang/nanodns/actions/workflows/release.yml)
[![codecov](https://codecov.io/gh/iyuangang/nanodns/graph/badge.svg?token=CODECOV_TOKEN)](https://codecov.io/gh/iyuangang/nanodns)
[![Docker Pulls](https://img.shields.io/docker/pulls/iyuangang/nanodns)](https://hub.docker.com/r/iyuangang/nanodns)
[![GHCR](https://img.shields.io/badge/GHCR-ghcr.io%2Fiyuangang%2Fnanodns-blue?logo=github)](https://github.com/iyuangang/nanodns/pkgs/container/nanodns)
[![OCI](https://img.shields.io/badge/OCI-compliant-blue?logo=opencontainers)](https://specs.opencontainers.org/)
[![Signed](https://img.shields.io/badge/cosign-keyless-green?logo=sigstore)](https://docs.sigstore.dev/)

---

## Features

| | |
|---|---|
| 🚀 **Zero dependencies** | Pure Python standard library — nothing to install beyond the package itself |
| 📝 **Single JSON config** | Human-readable, validated with `nanodns check`, hot-reloaded every 5 s |
| 🌐 **Full DNS record support** | A, AAAA, CNAME, MX, TXT, PTR, NS, SOA |
| 🃏 **Wildcard records** | `*.app.internal` catches all single-level subdomains |
| 🚫 **Domain blocking** | Instant NXDOMAIN via rewrite rules — no upstream query, sub-ms response |
| 🔄 **Upstream forwarding** | Unknown names forwarded to public DNS with automatic per-server failover |
| 💾 **LRU cache** | Configurable size and TTL cap; flushed automatically on config change |
| ♻️ **Hot reload** | File-mtime polling every 5 s; bad JSON is rejected and the old config kept |
| 🏥 **HTTP management API** | `/health`, `/ready`, `/metrics`, `/cluster`, `/reload`, `/sync` |
| 🔗 **Built-in HA sync** | Versioned push + pull replication; anti-rollback; automatic node catch-up |
| ⚡ **Async** | Single-process, asyncio-based — handles concurrent queries efficiently |
| 🐳 **Docker** | Distroless OCI image, `linux/amd64` + `linux/arm64`, cosign-signed |

---

## Installation

```bash
# PyPI  — CLI command is `nanodns`
pip install nanodns

# Docker
docker pull ghcr.io/iyuangang/nanodns:latest
```

Requires Python 3.10+.

---

## Quick Start

```bash
# Generate a starter config
nanodns init

# Check it
nanodns check nanodns.json

# Run on a high port (no root needed)
nanodns start --config nanodns.json --port 5353

# Verify
dig @127.0.0.1 -p 5353 web.internal.lan A   # Linux / macOS
nslookup web.internal.lan 127.0.0.1          # Windows
```

Port 53 in production:

```bash
sudo nanodns start --config nanodns.json
```

---

## Configuration

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 53,
    "upstream": ["8.8.8.8", "1.1.1.1"],
    "cache_enabled": true,
    "cache_ttl": 300,
    "cache_size": 1000,
    "log_level": "INFO",
    "log_queries": true,
    "hot_reload": true,
    "mgmt_port": 9053,
    "peers": []
  },
  "zones": {
    "internal.lan": {
      "soa": {
        "mname": "ns1.internal.lan",
        "rname": "admin.internal.lan",
        "serial": 2024010101,
        "refresh": 3600, "retry": 900, "expire": 604800, "minimum": 300
      },
      "ns": ["ns1.internal.lan"]
    }
  },
  "records": [
    { "name": "web.internal.lan",  "type": "A",     "value": "192.168.1.100", "ttl": 300 },
    { "name": "db.internal.lan",   "type": "A",     "value": "192.168.1.101" },
    { "name": "api.internal.lan",  "type": "CNAME", "value": "web.internal.lan" },
    { "name": "internal.lan",      "type": "MX",    "value": "mail.internal.lan", "priority": 10 },
    { "name": "app.internal.lan",  "type": "A",     "value": "192.168.1.200",
      "wildcard": true, "comment": "matches *.app.internal.lan" }
  ],
  "rewrites": [
    { "match": "*.ads.example.com", "action": "nxdomain" }
  ]
}
```

→ Full field reference in [USAGE.md](USAGE.md).

---

## CLI

```
nanodns start   --config FILE  [--host HOST] [--port PORT] [--log-level LEVEL] [--no-cache]
nanodns init    [OUTPUT]       Write an example config  (default: nanodns.json)
nanodns check   CONFIG         Validate a config file and print a summary
nanodns --version
```

---

## Record Types

| Type  | `value`              | Extra fields      |
|-------|----------------------|-------------------|
| A     | IPv4 address         | —                 |
| AAAA  | IPv6 address         | —                 |
| CNAME | Target hostname      | —                 |
| MX    | Mail server hostname | `priority` (int)  |
| TXT   | Text string          | —                 |
| PTR   | Pointer hostname     | —                 |
| NS    | Nameserver hostname  | —                 |

All types also accept: `ttl` (default `300` s), `wildcard` (bool), `comment` (string, ignored at runtime).

---

## HTTP Management API

Enable by setting `mgmt_port` to a non-zero value (recommended: `9053`).

| Endpoint      | Method | Description |
|---------------|--------|-------------|
| `/health`     | GET    | Liveness probe — `503` when unavailable (use with Keepalived / HAProxy) |
| `/ready`      | GET    | Readiness probe — `503` until config is loaded |
| `/metrics`    | GET    | Cache stats, record count, config version, uptime |
| `/cluster`    | GET    | This node plus every peer: version and reachability |
| `/config/raw` | GET    | Raw config JSON — fetched by peers during catch-up |
| `/reload`     | POST   | Reload from disk, bump version, push to all peers |
| `/sync`       | POST   | Accept a versioned config push from a peer (anti-rollback enforced) |

```bash
curl http://localhost:9053/health
curl -X POST http://localhost:9053/reload | python3 -m json.tool
curl http://localhost:9053/cluster | python3 -m json.tool
```

> **Security:** bind `mgmt_host` to an internal interface and keep `mgmt_port` off the public internet.

---

## High Availability

NanoDNS solves HA at two independent layers without any external dependencies.

### Traffic availability — network layer

DNS natively supports multiple nameservers. Pick the option that fits your infrastructure:

| Option | How | Failover time |
|--------|-----|---------------|
| Multiple nameservers in `/etc/resolv.conf` | Client retries next server on timeout | ~1–3 s |
| Keepalived floating VIP | VRRP detects unhealthy node via `/health`, moves IP | ~4 s |
| HAProxy UDP load balancer | Health-checks `/health`; removes unhealthy backends | ~4 s |
| Kubernetes Service | Readiness probe on `/ready`; pod removed from endpoints | ~5 s |

### Config consistency — application layer

NanoDNS keeps every node's config in sync using a versioned push/pull protocol.

**Push (online nodes):** any `POST /reload` bumps `config_version`, writes the new version to disk, applies it in memory, then calls `POST /sync` on every peer. A peer rejects a push whose version is lower than its own (`409 rejected_stale`), preventing accidental rollback.

**Pull (catch-up after restart):** 10 seconds after startup, the node queries every peer's `/health` to collect versions, pulls the full config from the highest peer via `GET /config/raw`, writes it to disk, and applies it — no operator action needed. This reconciliation repeats every 30 seconds.

| Scenario | Convergence |
|----------|-------------|
| Online node receives push | < 1 s |
| Restarted node catches up | 10–40 s |
| Periodic reconciliation | ≤ 30 s |

### 3-node cluster example

Each node's `peers` lists the management addresses of the other nodes. `config_version` is managed automatically — never edit it manually.

```json
{
  "server": {
    "port": 53,
    "mgmt_port": 9053,
    "peers": ["10.0.0.12:9053", "10.0.0.13:9053"],
    "config_version": 1
  }
}
```

| Node | `peers` |
|------|---------|
| ns1 `10.0.0.11` | `["10.0.0.12:9053", "10.0.0.13:9053"]` |
| ns2 `10.0.0.12` | `["10.0.0.11:9053", "10.0.0.13:9053"]` |
| ns3 `10.0.0.13` | `["10.0.0.11:9053", "10.0.0.12:9053"]` |

### Updating records (zero downtime)

```bash
# Edit config on any node, then:
curl -s -X POST http://localhost:9053/reload | python3 -m json.tool
# {
#   "status": "reloaded",
#   "version": 5,
#   "peers": {
#     "10.0.0.12:9053": {"status": "applied", "version": 5},
#     "10.0.0.13:9053": {"status": "applied", "version": 5}
#   }
# }
```

See **[USAGE.md → High Availability](USAGE.md#high-availability)** for complete deployment guides: Keepalived, HAProxy, Kubernetes, and Docker Compose.

---

## Docker

### Single node

```yaml
services:
  nanodns:
    image: ghcr.io/iyuangang/nanodns:latest
    restart: unless-stopped
    ports:
      - "53:53/udp"
      - "9053:9053/tcp"
    volumes:
      - ./nanodns.json:/etc/nanodns/nanodns.json
    cap_add: [NET_BIND_SERVICE]
```

### 3-node HA cluster

The project ships a ready-to-use `docker-compose.yml`:

```bash
docker compose up -d
```

### Image reference

| Tag | Description |
|-----|-------------|
| `latest` | Latest stable release |
| `1.2.3` | Pinned to an exact version |
| `sha-a1b2c3` | Pinned to a specific commit |

Platforms: `linux/amd64` · `linux/arm64`

Built on [Chainguard distroless Python](https://images.chainguard.dev/). Verify the signature:

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/iyuangang/nanodns/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/iyuangang/nanodns:latest
```

---

## Deployment

### Linux — systemd

```ini
# /etc/systemd/system/nanodns.service
[Unit]
Description=NanoDNS Server
After=network.target

[Service]
ExecStart=/usr/local/bin/nanodns start --config /etc/nanodns/nanodns.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now nanodns
sudo journalctl -u nanodns -f
```

### Windows — NSSM service

```powershell
# Run as Administrator
nssm install NanoDNS "C:\Python\Scripts\nanodns.exe"
nssm set NanoDNS AppParameters "start --config C:\dns\nanodns.json"
nssm start NanoDNS
```

---

## CI/CD

### Commit prefix conventions

| Prefix | Tests | Docker build | PyPI publish |
|--------|-------|--------------|--------------|
| `feat` `fix` `perf` `refactor` | ✅ | ✅ on `main` | 🏷️ on tag |
| `test` `ci` `build` | ✅ | ⏭️ skip | ⏭️ skip |
| `docs` `style` `chore` | ⏭️ skip | ⏭️ skip | ⏭️ skip |

### Releasing a new version

```bash
# 1. Bump version in pyproject.toml and nanodns/__init__.py
# 2. Commit, tag, push
git add pyproject.toml nanodns/__init__.py
git commit -m "chore: bump version to 0.2.0"
git tag v0.2.0 && git push origin main --tags
# PyPI (nanodns) and Docker publish automatically
```

---

## License

[MIT](LICENSE)
