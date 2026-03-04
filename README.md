# NanoDNS

> A lightweight, zero-dependency DNS server for internal networks — configured with a single JSON file.

[![PyPI version](https://img.shields.io/pypi/v/nanodns.svg)](https://pypi.org/project/nanodns/)
[![Python](https://img.shields.io/pypi/pyversions/nanodns.svg)](https://pypi.org/project/nanodns/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/yourname/nanodns/actions/workflows/release.yml/badge.svg)](https://github.com/yourname/nanodns/actions/workflows/release.yml)
[![Tests](https://github.com/yourname/nanodns/actions/workflows/test.yml/badge.svg)](https://github.com/yourname/nanodns/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/yourname/nanodns/graph/badge.svg?token=CODECOV_TOKEN)](https://codecov.io/gh/yourname/nanodns)
[![Docker Pulls](https://img.shields.io/docker/pulls/yourname/nanodns)](https://hub.docker.com/r/yourname/nanodns)
[![GHCR](https://img.shields.io/badge/GHCR-ghcr.io%2Fyourname%2Fnanodns-blue?logo=github)](https://github.com/yourname/nanodns/pkgs/container/nanodns)
[![OCI](https://img.shields.io/badge/OCI-compliant-blue?logo=opencontainers)](https://specs.opencontainers.org/)
[![Signed](https://img.shields.io/badge/cosign-keyless-green?logo=sigstore)](https://docs.sigstore.dev/)

---

## Features

- 🚀 **Zero dependencies** — pure Python standard library only
- 📝 **JSON config** — human-readable, hot-reloadable configuration
- 🔄 **Upstream forwarding** — forwards unknown queries to public DNS
- 💾 **LRU Cache** — configurable in-memory response cache with TTL
- 🌐 **Record types** — A, AAAA, CNAME, MX, TXT, PTR, NS, SOA
- 🃏 **Wildcard records** — `*.example.internal` support
- 🚫 **Rewrites / blocking** — NXDOMAIN any domain instantly
- ♻️ **Hot reload** — config changes applied without restart
- ⚡ **Async** — built on Python asyncio
- 🐳 **Docker** — multi-platform OCI image (`amd64` + `arm64`)
- 🔏 **Signed** — cosign keyless signatures via Sigstore

---

## Installation

### pip

```bash
pip install nanodns
```

### Docker

```bash
# GitHub Container Registry (recommended)
docker pull ghcr.io/yourname/nanodns:latest

# Docker Hub
docker pull yourname/nanodns:latest
```

---

## Quick Start

### pip

```bash
# 1. Generate an example config
nanodns init

# 2. Edit nanodns.json to your needs

# 3. Validate config
nanodns check nanodns.json

# 4. Start on a high port (no admin rights needed)
nanodns start --config nanodns.json --port 5353

# 5. Start on port 53 (requires root / Administrator)
sudo nanodns start --config nanodns.json
```

### Docker

```bash
# Generate a config first
nanodns init nanodns.json

# Run with Docker
docker run -d \
  --name nanodns \
  -p 53:53/udp \
  -v $(pwd)/nanodns.json:/etc/nanodns.json:ro \
  --cap-add NET_BIND_SERVICE \
  ghcr.io/yourname/nanodns:latest

# Run with Docker Compose
docker compose up -d
```

### Verify it works

```bash
# Linux / macOS
dig @127.0.0.1 -p 5353 web.internal.lan A

# Windows (cmd)
nslookup web.internal.lan 127.0.0.1

# Windows (PowerShell)
Resolve-DnsName -Name web.internal.lan -Server 127.0.0.1 -Type A
```

---

## Configuration

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 53,
    "upstream": ["8.8.8.8", "1.1.1.1"],
    "upstream_timeout": 3,
    "upstream_port": 53,
    "cache_enabled": true,
    "cache_ttl": 300,
    "cache_size": 1000,
    "log_level": "INFO",
    "log_queries": true,
    "hot_reload": true
  },
  "zones": {
    "internal.lan": {
      "soa": {
        "mname": "ns1.internal.lan",
        "rname": "admin.internal.lan",
        "serial": 2024010101,
        "refresh": 3600,
        "retry": 900,
        "expire": 604800,
        "minimum": 300
      },
      "ns": ["ns1.internal.lan"]
    }
  },
  "records": [
    { "name": "ns1.internal.lan",  "type": "A",     "value": "192.168.1.10",  "ttl": 3600 },
    { "name": "web.internal.lan",  "type": "A",     "value": "192.168.1.100", "ttl": 300  },
    { "name": "db.internal.lan",   "type": "A",     "value": "192.168.1.101", "ttl": 300  },
    { "name": "api.internal.lan",  "type": "CNAME", "value": "web.internal.lan"            },
    { "name": "ipv6.internal.lan", "type": "AAAA",  "value": "fd00::1",       "ttl": 300  },
    { "name": "internal.lan",      "type": "MX",    "value": "mail.internal.lan", "priority": 10 },
    { "name": "internal.lan",      "type": "TXT",   "value": "v=spf1 ip4:192.168.1.0/24 ~all" },
    {
      "name": "app.internal.lan",
      "type": "A",
      "value": "192.168.1.200",
      "wildcard": true,
      "comment": "Matches *.app.internal.lan"
    }
  ],
  "rewrites": [
    { "match": "ads.doubleclick.net", "action": "nxdomain" },
    { "match": "*.tracker.example",   "action": "nxdomain" }
  ]
}
```

See [USAGE.md](USAGE.md) for the full configuration reference.

---

## CLI Reference

```
nanodns start  --config FILE  [--host HOST] [--port PORT] [--log-level LEVEL] [--no-cache]
nanodns init   [OUTPUT]       Generate an example config file
nanodns check  CONFIG         Validate a config file and print a summary
nanodns --version
```

---

## Record Types

| Type  | `value`              | Extra fields     |
|-------|----------------------|------------------|
| A     | IPv4 address         | —                |
| AAAA  | IPv6 address         | —                |
| CNAME | Target hostname      | —                |
| MX    | Mail server hostname | `priority` (int) |
| TXT   | Text string          | —                |
| PTR   | Pointer hostname     | —                |
| NS    | Nameserver hostname  | —                |

All records support: `ttl` (default `300`), `wildcard` (bool), `comment` (string).

---

## Docker

### Images

| Registry   | Image                              |
|------------|------------------------------------|
| GHCR       | `ghcr.io/yourname/nanodns`         |
| Docker Hub | `yourname/nanodns`                 |

### Tags

| Tag         | Description               |
|-------------|---------------------------|
| `latest`    | Latest stable release     |
| `1.2.3`     | Exact version             |
| `1.2`       | Minor version             |
| `1`         | Major version             |
| `sha-a1b2c3`| Specific commit (main)    |

### Platforms

`linux/amd64` · `linux/arm64` (Raspberry Pi 4+, Apple Silicon via emulation)

### docker-compose.yml

```yaml
services:
  nanodns:
    image: ghcr.io/yourname/nanodns:latest
    container_name: nanodns
    restart: unless-stopped
    ports:
      - "53:53/udp"
    volumes:
      - ./nanodns.json:/etc/nanodns.json:ro
    cap_add:
      - NET_BIND_SERVICE
    read_only: true
```

### OCI Compliance & Supply Chain Security

Images are built on [Chainguard distroless Python](https://images.chainguard.dev/directory/image/python/overview) and follow the [OCI Image Spec](https://specs.opencontainers.org/image-spec/) with standard annotations.

```bash
# Inspect OCI annotations
docker inspect ghcr.io/yourname/nanodns:latest \
  --format '{{json .Config.Labels}}' | python3 -m json.tool

# Verify cosign keyless signature (Sigstore)
cosign verify \
  --certificate-identity-regexp="https://github.com/yourname/nanodns/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/yourname/nanodns:latest
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

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now nanodns
```

### Windows — NSSM

```powershell
nssm install NanoDNS "C:\Python\Scripts\nanodns.exe"
nssm set NanoDNS AppParameters "start --config C:\dns\nanodns.json"
nssm start NanoDNS
```

### High Port (No Root Required)

```bash
nanodns start --config nanodns.json --port 5353

# Redirect port 53 → 5353 with iptables (Linux)
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
```

---

## CI / CD

### Commit Convention

Commit prefix determines what runs in CI:

| Prefix | Tests | Docker build | PyPI release |
|--------|-------|--------------|--------------|
| `feat` `fix` `perf` `refactor` | ✅ | ✅ on main | 🏷️ on tag |
| `test` `ci` `build` | ✅ | ⏭️ skip | ⏭️ skip |
| `docs` `style` `chore` | ⏭️ skip | ⏭️ skip | ⏭️ skip |

### Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `test.yml` | every push / PR | Unit + integration tests across 3 OS × 3 Python versions; uploads coverage to Codecov |
| `release.yml` | `v*` tag / `main` | Full pipeline: test → build → summary → GitHub Release → PyPI → Docker |

### Release a new version

```bash
# 1. Bump version in pyproject.toml
# 2. Commit and tag
git add pyproject.toml
git commit -m "chore: bump version to 0.2.0"
git tag v0.2.0
git push origin main --tags
```

PyPI and Docker Hub are published automatically on tag push.

---

## License

[MIT](LICENSE)