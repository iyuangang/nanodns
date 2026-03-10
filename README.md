<div align="center">

# NanoDNS

**A lightweight internal DNS server — one JSON file, runs anywhere Python runs.**

[![PyPI version](https://img.shields.io/pypi/v/nanodns.svg)](https://pypi.org/project/nanodns/)
[![Python](https://img.shields.io/pypi/pyversions/nanodns.svg)](https://pypi.org/project/nanodns/)
[![Release](https://github.com/iyuangang/nanodns/actions/workflows/release.yml/badge.svg)](https://github.com/iyuangang/nanodns/actions/workflows/release.yml)
[![Coverage](https://codecov.io/gh/iyuangang/nanodns/graph/badge.svg?token=CODECOV_TOKEN)](https://codecov.io/gh/iyuangang/nanodns)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GHCR](https://img.shields.io/badge/image-ghcr.io-blue?logo=github)](https://github.com/iyuangang/nanodns/pkgs/container/nanodns)
[![OCI](https://img.shields.io/badge/OCI-compliant-blue?logo=opencontainers)](https://specs.opencontainers.org/)
[![Signed](https://img.shields.io/badge/cosign-keyless-green?logo=sigstore)](https://docs.sigstore.dev/)

</div>

---

```bash
pip install nanodns
nanodns start                      # listening on :53 in 2 seconds
```

```json
{ "records": [
    { "name": "dev.local",  "type": "A", "value": "192.168.1.10" },
    { "name": "*.dev.local","type": "A", "value": "192.168.1.10", "wildcard": true }
]}
```

```bash
$ dig @127.0.0.1 api.dev.local +short
192.168.1.10                       # wildcard matched — no restart needed
```

---

## Why NanoDNS?

You just need internal DNS for your homelab, a small team, or a dev environment.
You don't need a 300 MB container with a web UI, a PostgreSQL backend, or a
BIND config file that requires a PhD to edit.

| | NanoDNS | Pi-hole | CoreDNS | dnsmasq |
|---|:---:|:---:|:---:|:---:|
| Zero pip dependencies | ✅ | ❌ | ❌ | ❌ |
| Built-in multi-node HA sync | ✅ | ❌ | ❌ | ❌ |
| Edit config with any text editor | ✅ | ⚠️ | ⚠️ | ⚠️ |
| Hot-reload without restart | ✅ | ❌ | ✅ | ❌ |

> **NanoDNS is for people who want DNS to be boring** — not a project in itself.

---

## What people use it for

**Homelab internal DNS**
Replace your router's dnsmasq with something you can actually version-control.
Push a config change from your laptop, all nodes sync in under a second.

**Dev environment**
`*.svc.local → 127.0.0.1` with one wildcard record.  No `/etc/hosts` hacks,
no docker network DNS, no Consul.  Edit JSON, it reloads.

**Small private cloud (2–5 nodes)**
No Kubernetes, no CoreDNS Helm chart.  Three VMs, three NanoDNS instances,
peers set to each other's IPs.  They stay in sync automatically.

**Block unwanted domains**
Add rewrite rules that return NXDOMAIN instantly.  No upstream query, sub-ms
response, no separate blocklist service needed.

---

## 30-second quick start

```bash
# Install
pip install nanodns

# Create a config
nanodns init           # writes nanodns.json in the current directory

# Validate it
nanodns check nanodns.json

# Run on a non-privileged port to test
nanodns start --port 5353

# Query it
dig @127.0.0.1 -p 5353 web.internal A
```

Port 53 (requires root or `CAP_NET_BIND_SERVICE`):

```bash
sudo nanodns start --config /etc/nanodns/nanodns.json
```

---

## Configuration in full

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
    "log_queries": false,
    "hot_reload": true,
    "mgmt_port": 9053,
    "peers": []
  },
  "zones": {
    "internal.lan": {
      "soa": {
        "mname": "ns1.internal.lan", "rname": "admin.internal.lan",
        "serial": 2024010101, "refresh": 3600, "retry": 900,
        "expire": 604800, "minimum": 300
      },
      "ns": ["ns1.internal.lan"]
    }
  },
  "records": [
    { "name": "web.internal.lan",   "type": "A",     "value": "192.168.1.100", "ttl": 300 },
    { "name": "db.internal.lan",    "type": "A",     "value": "192.168.1.101" },
    { "name": "api.internal.lan",   "type": "CNAME", "value": "web.internal.lan" },
    { "name": "internal.lan",       "type": "MX",    "value": "mail.internal.lan", "priority": 10 },
    { "name": "*.app.internal.lan", "type": "A",     "value": "192.168.1.200", "wildcard": true }
  ],
  "rewrites": [
    { "match": "ads.example.com",   "action": "nxdomain" },
    { "match": "*.tracker.net",     "action": "nxdomain" }
  ]
}
```

**Every change to this file is detected within 5 seconds and applied live —
no restart, no dropped queries, no operator action required.**

→ Full reference: [USAGE.md](docs/USAGE.md)

---

## Record types

| Type  | `value` field          | Extra fields         |
|-------|------------------------|----------------------|
| `A`   | IPv4 address           | —                    |
| `AAAA`| IPv6 address           | —                    |
| `CNAME`| Target hostname       | —                    |
| `MX`  | Mail server hostname   | `priority` (int)     |
| `TXT` | Text string            | —                    |
| `PTR` | Pointer hostname       | —                    |
| `NS`  | Nameserver hostname    | —                    |

All records also accept: `ttl` (seconds, default `300`), `wildcard` (bool),
`comment` (string, ignored at runtime).

---

## Multi-node HA

No Zookeeper. No Raft. No etcd. Just point each node at its peers.

```json
{
  "server": {
    "mgmt_port": 9053,
    "peers": ["10.0.0.12:9053", "10.0.0.13:9053"]
  }
}
```

**How sync works:**

1. Edit config on **any** node.
2. `curl -X POST http://localhost:9053/reload`
3. NanoDNS bumps the version, applies in memory, pushes to all peers in < 1 s.
4. Nodes that were offline catch up automatically when they come back —
   they pull the latest config from the highest-versioned peer, with no
   operator action required.

```
$ curl -s http://localhost:9053/cluster | python3 -m json.tool
{
  "this": { "version": 5, "status": "healthy" },
  "peers": {
    "10.0.0.12:9053": { "version": 5, "status": "synced" },
    "10.0.0.13:9053": { "version": 5, "status": "synced" }
  }
}
```

| Scenario | Convergence time |
|----------|-----------------|
| Reload pushed to online peers | < 1 s |
| Node reboots and catches up | 10–40 s |
| Periodic background reconciliation | ≤ 30 s |

For traffic-level HA (floating VIP, HAProxy UDP, Kubernetes Service) see
[USAGE.md → High Availability](docs/USAGE.md#high-availability).

---

## HTTP management API

Enable with `mgmt_port` in config (recommended: `9053`).

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness — 503 when unavailable |
| `/ready` | GET | Readiness — 503 until config loaded |
| `/metrics` | GET | Cache stats, query count, uptime, version |
| `/cluster` | GET | All nodes with version + reachability |
| `/config/raw` | GET | Raw config JSON (used by peer catch-up) |
| `/reload` | POST | Reload from disk, bump version, push to peers |
| `/sync` | POST | Accept a versioned config push from a peer |

> Bind `mgmt_host` to an internal interface only. Keep `mgmt_port` off the internet.

---

## CLI

```
nanodns start   --config FILE [--host HOST] [--port PORT] [--log-level LEVEL] [--no-cache]
nanodns init    [OUTPUT]       Write an example config  (default: ./nanodns.json)
nanodns check   CONFIG         Validate config and print a summary
nanodns --version
```

---

## Docker

```yaml
# docker-compose.yml — single node
services:
  nanodns:
    image: ghcr.io/iyuangang/nanodns:latest
    restart: unless-stopped
    ports:
      - "53:53/udp"
      - "9053:9053/tcp"
    volumes:
      - ./nanodns.json:/etc/nanodns/nanodns.json:ro
    cap_add: [NET_BIND_SERVICE]
```

3-node cluster — the repo ships a ready-to-use `docker-compose.yml`:

```bash
git clone https://github.com/iyuangang/nanodns
cd nanodns && docker compose up -d
```

Image tags: `latest` · `1.2.3` (pinned) · `sha-a1b2c3` (commit)  
Platforms: `linux/amd64` · `linux/arm64`  
Base: [Chainguard distroless Python](https://images.chainguard.dev/) — no shell, no package manager, minimal CVE surface.

Verify the image signature:

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/iyuangang/nanodns/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/iyuangang/nanodns:latest
```

---

## systemd (Linux production)

```bash
pip install nanodns
sudo cp /etc/systemd/system/nanodns.service << 'EOF'
[Unit]
Description=NanoDNS Server
After=network.target

[Service]
ExecStart=/usr/local/bin/nanodns start --config /etc/nanodns/nanodns.json
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now nanodns
sudo journalctl -u nanodns -f
```

Or use the RPM / DEB packages in the [releases page](https://github.com/iyuangang/nanodns/releases) — they install the unit file automatically.

---

## Windows

```powershell
pip install nanodns
nanodns start --config C:\dns\nanodns.json --port 5353   # test first

# Install as a service with NSSM (https://nssm.cc)
nssm install NanoDNS "C:\Python\Scripts\nanodns.exe"
nssm set NanoDNS AppParameters "start --config C:\dns\nanodns.json"
nssm start NanoDNS
```

---

## Packages (RPM / DEB)

Pre-built packages are available on the [releases page](https://github.com/iyuangang/nanodns/releases).

```bash
# RHEL / Rocky Linux / AlmaLinux / Fedora
sudo dnf install ./nanodns-*.noarch.rpm

# Debian / Ubuntu
sudo apt install ./nanodns_*.deb
```

Or build from source (no system packaging tools needed):

```bash
python3 packaging/build_rpm.py          # → dist/nanodns-*.rpm
python3 packaging/build_deb.py          # → dist/nanodns_*.deb
python3 packaging/build_packages.py --all   # both at once
```

---

## Contributing

```bash
git clone https://github.com/iyuangang/nanodns
cd nanodns
pip install -e ".[dev]"
pytest                  # 202 tests, ~7 s
pytest --cov            # coverage ≥ 90 % enforced
```

Commit prefix → CI behaviour:

| Prefix | Tests | Docker build | PyPI publish |
|--------|:-----:|:------------:|:------------:|
| `feat` `fix` `perf` `refactor` | ✅ | ✅ on `main` | 🏷️ on tag |
| `test` `ci` `build` | ✅ | ⏭️ skip | ⏭️ skip |
| `docs` `style` `chore` | ⏭️ skip | ⏭️ skip | ⏭️ skip |

Bug reports, feature requests, and PRs are all welcome.

---

## License

[MIT](LICENSE)