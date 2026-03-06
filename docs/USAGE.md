# NanoDNS — Usage Guide

Complete reference for installation, configuration, deployment, and high availability.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Configuration Reference](#configuration-reference)
  - [server](#server)
  - [zones](#zones)
  - [records](#records)
  - [rewrites](#rewrites)
- [Record Types](#record-types)
- [Wildcard Records](#wildcard-records)
- [Domain Blocking](#domain-blocking)
- [Hot Reload](#hot-reload)
- [Caching](#caching)
- [Upstream Forwarding](#upstream-forwarding)
- [HTTP Management API](#http-management-api)
- [High Availability](#high-availability)
  - [How Config Sync Works](#how-config-sync-works)
  - [Option 1: Multiple Nameservers](#option-1-multiple-nameservers)
  - [Option 2: Keepalived Floating VIP](#option-2-keepalived-floating-vip)
  - [Option 3: HAProxy UDP Load Balancer](#option-3-haproxy-udp-load-balancer)
  - [Option 4: Kubernetes](#option-4-kubernetes)
  - [Option 5: Docker Compose Cluster](#option-5-docker-compose-cluster)
  - [Config Update Runbook](#config-update-runbook)
- [Single-Node Deployment](#single-node-deployment)
  - [Linux systemd](#linux-systemd)
  - [Windows Service](#windows-service)
  - [Docker Single Node](#docker-single-node)
- [Client Configuration](#client-configuration)
- [Testing and Verification](#testing-and-verification)
- [FAQ](#faq)

---

## Installation

**Requires Python 3.10 or later.**

```bash
# Install from PyPI — the CLI command is `nanodns`
pip install nanodns

# From source
git clone https://github.com/iyuangang/nanodns.git
cd nanodns
pip install .

# Verify
nanodns --version
```

---

## Quick Start

```bash
# 1. Generate an example config
nanodns init

# 2. Edit records to match your network
vim nanodns.json

# 3. Validate the file
nanodns check nanodns.json

# 4. Start on a high port (no root needed)
nanodns start --config nanodns.json --port 5353

# 5. Test it
dig @127.0.0.1 -p 5353 web.internal.lan A    # Linux / macOS
nslookup web.internal.lan 127.0.0.1           # Windows
```

To bind the standard port 53, run with elevated privileges:

```bash
sudo nanodns start --config nanodns.json          # Linux / macOS
# Windows: run the command prompt as Administrator
nanodns start --config nanodns.json
```

---

## CLI Reference

### `nanodns start`

Start the DNS server.

| Flag | Default | Description |
|------|---------|-------------|
| `--config, -c FILE` | *(required)* | Path to the JSON config file |
| `--host HOST` | from config | Override the listen address |
| `--port, -p PORT` | from config | Override the listen port |
| `--log-level LEVEL` | from config | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `--no-cache` | — | Disable the response cache for this session |

```bash
# Verbose debug session, no caching
nanodns start --config nanodns.json --port 5353 --log-level DEBUG --no-cache

# Production — reads host/port from the config file
sudo nanodns start --config /etc/nanodns/nanodns.json
```

### `nanodns init`

Write a fully-commented example config file.

```bash
nanodns init                        # writes ./nanodns.json
nanodns init /etc/nanodns/my.json   # write to an explicit path
```

### `nanodns check`

Validate a config file and print a human-readable summary. Exits non-zero on any error.

```bash
nanodns check nanodns.json
```

```
OK Config is valid.
  Records : 8
  Zones   : 1
  Rewrites: 2
  Upstream: ['8.8.8.8', '1.1.1.1']
  Listen  : 0.0.0.0:53
```

---

## Configuration Reference

The config file is JSON with four top-level keys: `server`, `zones`, `records`, `rewrites`.

### server

Full example with every supported field:

```json
{
  "server": {
    "host":             "0.0.0.0",
    "port":             53,
    "upstream":         ["8.8.8.8", "1.1.1.1"],
    "upstream_timeout": 3,
    "upstream_port":    53,
    "cache_enabled":    true,
    "cache_ttl":        300,
    "cache_size":       1000,
    "log_level":        "INFO",
    "log_queries":      true,
    "hot_reload":       true,
    "mgmt_host":        "0.0.0.0",
    "mgmt_port":        9053,
    "peers":            [],
    "config_version":   1
  }
}
```

**Core fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | `"0.0.0.0"` | DNS listen address; `0.0.0.0` binds all interfaces |
| `port` | int | `53` | DNS listen port; port 53 requires root |
| `upstream` | string[] | `["8.8.8.8","1.1.1.1"]` | Upstream resolvers, tried in order on cache miss |
| `upstream_timeout` | int | `3` | Seconds before a single upstream attempt is abandoned |
| `upstream_port` | int | `53` | Port used when contacting upstream resolvers |
| `cache_enabled` | bool | `true` | Enable the LRU response cache |
| `cache_ttl` | int | `300` | Maximum TTL stored in cache (upstream TTLs are capped to this) |
| `cache_size` | int | `1000` | Maximum cache entries; LRU eviction when exceeded |
| `log_level` | string | `"INFO"` | One of: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `log_queries` | bool | `true` | Print a log line for every resolved query |
| `hot_reload` | bool | `true` | Poll config file mtime every 5 s and reload on change |

**HA fields** (only needed for multi-node clusters):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mgmt_host` | string | `"0.0.0.0"` | Management API listen address; restrict to an internal interface in production |
| `mgmt_port` | int | `0` | Management API port; **`0` = disabled**; recommended value: `9053` |
| `peers` | string[] | `[]` | Management addresses of peer nodes, in `"host:port"` format |
| `config_version` | int | `1` | Monotonic version counter — **managed automatically, never edit by hand** |

> **Security:** `mgmt_port` provides unauthenticated access to reload and inspect config. Bind it to an internal-only interface and firewall it from the public internet.

---

### zones

Defines authoritative zones. A query for any name that falls within a declared zone but has no matching record returns `NXDOMAIN` — it is not forwarded upstream. This lets you own an entire private domain cleanly.

```json
{
  "zones": {
    "internal.lan": {
      "soa": {
        "mname":   "ns1.internal.lan",
        "rname":   "admin.internal.lan",
        "serial":  2024010101,
        "refresh": 3600,
        "retry":   900,
        "expire":  604800,
        "minimum": 300
      },
      "ns": ["ns1.internal.lan"]
    }
  }
}
```

| SOA field | Description |
|-----------|-------------|
| `mname` | Primary nameserver hostname |
| `rname` | Admin contact — use `.` instead of `@` in the email address |
| `serial` | Zone serial number; increment it when records change |
| `refresh` | How often secondary servers poll for updates (seconds) |
| `retry` | Retry interval when a refresh fails (seconds) |
| `expire` | How long a secondary serves stale data without a successful refresh (seconds) |
| `minimum` | Negative-response cache TTL (seconds) |

`zones` is optional. Without it, any unmatched query is forwarded to the upstream resolvers rather than returning `NXDOMAIN`.

---

### records

An array of DNS record objects. Common fields:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | ✅ | — | Fully-qualified hostname |
| `type` | string | ✅ | — | Record type (see [Record Types](#record-types)) |
| `value` | string | ✅ | — | Record data; format depends on type |
| `ttl` | int | ❌ | `300` | Time-to-live in seconds |
| `wildcard` | bool | ❌ | `false` | Match all direct subdomains of `name` |
| `comment` | string | ❌ | `""` | Free-text note; ignored at runtime |

MX records also accept `priority` (int, default `10`; lower value = higher preference).

```json
{
  "records": [
    { "name": "web.internal.lan",  "type": "A",   "value": "192.168.1.100", "ttl": 60  },
    { "name": "internal.lan",      "type": "MX",  "value": "mail.internal.lan", "priority": 10 },
    { "name": "app.internal.lan",  "type": "A",   "value": "192.168.1.200", "wildcard": true }
  ]
}
```

---

### rewrites

Rewrite rules are evaluated before local records. Any matched query returns `NXDOMAIN` immediately — no upstream lookup, no cache write.

```json
{
  "rewrites": [
    { "match": "ads.example.com",    "action": "nxdomain", "comment": "block ads" },
    { "match": "*.tracker.example",  "action": "nxdomain" }
  ]
}
```

| Field | Description |
|-------|-------------|
| `match` | Exact hostname, or a `*.` wildcard prefix |
| `action` | Currently only `nxdomain` is supported |
| `comment` | Optional note; ignored at runtime |

---

## Record Types

### A — IPv4 address

```json
{ "name": "web.internal.lan", "type": "A", "value": "192.168.1.100" }
```

Multiple A records for the same name are all returned; most clients round-robin across them automatically.

```json
{ "name": "web.internal.lan", "type": "A", "value": "192.168.1.100" },
{ "name": "web.internal.lan", "type": "A", "value": "192.168.1.101" }
```

### AAAA — IPv6 address

```json
{ "name": "web.internal.lan", "type": "AAAA", "value": "fd00::1" }
```

### CNAME — Alias

```json
{ "name": "api.internal.lan", "type": "CNAME", "value": "web.internal.lan" }
```

The client follows the CNAME and resolves the target separately.

### MX — Mail exchanger

```json
{ "name": "internal.lan", "type": "MX", "value": "mail1.internal.lan", "priority": 10 },
{ "name": "internal.lan", "type": "MX", "value": "mail2.internal.lan", "priority": 20 }
```

Lower `priority` value = higher preference.

### TXT — Text record

```json
{ "name": "internal.lan", "type": "TXT", "value": "v=spf1 ip4:192.168.1.0/24 ~all" }
```

### PTR — Reverse lookup

```json
{ "name": "100.1.168.192.in-addr.arpa", "type": "PTR", "value": "web.internal.lan" }
```

### NS — Nameserver delegation

```json
{ "name": "internal.lan", "type": "NS", "value": "ns1.internal.lan" }
```

---

## Wildcard Records

Set `"wildcard": true` to match every direct (single-level) subdomain of a name:

```json
{
  "name":     "app.internal.lan",
  "type":     "A",
  "value":    "192.168.1.200",
  "wildcard": true,
  "comment":  "catch-all for *.app.internal.lan"
}
```

| Query | Result |
|-------|--------|
| `foo.app.internal.lan` | `192.168.1.200` ✅ |
| `bar.app.internal.lan` | `192.168.1.200` ✅ |
| `a.b.app.internal.lan` | no match ❌ — only one level deep |

---

## Domain Blocking

Any hostname can be blocked instantly using a rewrite rule. Blocked queries never reach upstream resolvers.

```json
{
  "rewrites": [
    { "match": "doubleclick.net",         "action": "nxdomain" },
    { "match": "*.doubleclick.net",       "action": "nxdomain" },
    { "match": "*.googlesyndication.com", "action": "nxdomain" }
  ]
}
```

Response time for blocked names is sub-millisecond.

---

## Hot Reload

When `hot_reload: true`, NanoDNS polls the config file's modification time every 5 seconds. When a change is detected:

1. The new config is parsed and validated.
2. If valid, records are swapped in and the cache is flushed.
3. If invalid (e.g. broken JSON), the error is logged and the existing config continues serving — no downtime.

In HA mode, a successful reload also pushes the new config to all peers (idempotent: no push if the checksum is unchanged).

To reload immediately without waiting:

```bash
# Via the management API — also propagates to peers
curl -X POST http://localhost:9053/reload

# Or just restart the process
sudo systemctl restart nanodns
```

---

## Caching

Upstream query responses are cached in an LRU cache:

- **TTL capping:** cached TTL = `min(upstream TTL, cache_ttl)`. This prevents a record with a very long upstream TTL from sitting in the cache indefinitely.
- **Eviction:** when the number of entries exceeds `cache_size`, the least-recently-used entry is removed.
- **Local records:** records defined in the `records` array are served directly and are never cached.
- **Automatic flush:** the cache is cleared on every hot reload and on every successful peer sync.

To disable caching entirely for a debugging session:

```bash
nanodns start --config nanodns.json --port 5353 --no-cache
```

---

## Upstream Forwarding

Any query that does not match a local record or rewrite rule is forwarded to the `upstream` resolvers:

1. Resolvers are tried in the order listed.
2. If a resolver times out (after `upstream_timeout` seconds), the next one is tried.
3. If every resolver fails, the client receives `SERVFAIL`.

Popular upstream choices:

| Provider | Addresses |
|----------|-----------|
| Google | `8.8.8.8`, `8.8.4.4` |
| Cloudflare | `1.1.1.1`, `1.0.0.1` |
| Quad9 | `9.9.9.9` |
| Tencent DNSPod | `119.29.29.29` |
| Alibaba | `223.5.5.5`, `223.6.6.6` |

---

## HTTP Management API

The management server starts when `mgmt_port` is set to a non-zero value. All endpoints return JSON unless otherwise noted.

### Endpoint reference

| Endpoint | Method | Success code | Description |
|----------|--------|-------------|-------------|
| `/health` | GET | `200` | Liveness probe — returns `503` when the server cannot serve queries |
| `/ready` | GET | `200` | Readiness probe — returns `503` until a valid config is loaded |
| `/metrics` | GET | `200` | Cache statistics, record count, config version, uptime |
| `/cluster` | GET | `200` | This node and all configured peers: version, status, reachability |
| `/config/raw` | GET | `200` | The raw config JSON bytes — used by peers during catch-up |
| `/reload` | POST | `200` | Reload config from disk, increment version, push to all peers |
| `/sync` | POST | `200` / `409` | Accept a versioned config push from a peer; `409` if stale |

### Response examples

```bash
# /health
curl http://localhost:9053/health
# {"status": "ok", "version": 5, "uptime_s": 7200.0}

# /metrics
curl http://localhost:9053/metrics | python3 -m json.tool
# {
#   "uptime_s": 7200.0,
#   "version": 5,
#   "checksum": "a3f8b2c1d4e5f601",
#   "records": 12,
#   "zones": 2,
#   "cache": {
#     "size": 42,
#     "hits": 3100,
#     "misses": 80,
#     "hit_rate": 97.5
#   }
# }

# /cluster
curl http://localhost:9053/cluster | python3 -m json.tool
# {
#   "self":  {"status": "ok", "version": 5, "records": 12},
#   "peers": {
#     "10.0.0.12:9053": {"reachable": true, "version": 5, "status": "ok"},
#     "10.0.0.13:9053": {"reachable": true, "version": 5, "status": "ok"}
#   }
# }

# /reload
curl -s -X POST http://localhost:9053/reload | python3 -m json.tool
# {
#   "status": "reloaded",
#   "version": 6,
#   "records": 13,
#   "peers": {
#     "10.0.0.12:9053": {"status": "applied", "version": 6},
#     "10.0.0.13:9053": {"status": "applied", "version": 6}
#   }
# }
```

---

## High Availability

### How Config Sync Works

HA has two completely independent concerns — each solved at a different layer.

**Traffic availability** is a network-layer problem. The DNS protocol already supports multiple resolvers; clients retry the next one automatically when a server is unreachable. For a single-IP entry point, add Keepalived or HAProxy in front.

**Config consistency** is an application-layer problem solved by NanoDNS's built-in sync protocol.

#### Push path (online nodes)

```
Operator edits nanodns.json on any node and calls POST /reload
  → version = max(disk_version, memory_version) + 1
  → write updated JSON (including new version) back to disk
  → swap config in memory — DNS transport never pauses
  → call POST /sync on every peer

Each peer evaluates the incoming push:
  checksum matches mine  →  200 already_current   (no-op, idempotent)
  incoming version < mine →  409 rejected_stale   (anti-rollback)
  incoming version ≥ mine →  write to disk → apply → 200 applied
```

#### Pull path (restart catch-up)

```
A node restarts after being offline during config changes
  10 s after startup, _reconcile_peers() fires:
    1. GET /health on every peer → collect versions
    2. Identify the peer with the highest version
    3. GET /config/raw from that peer
    4. Write to disk and apply in memory
    5. Push the new version to any other peers that are also behind
  This loop repeats every 30 s for ongoing consistency
```

The `config_version` counter is strictly monotonic. A push carrying an older version is rejected with `409 Conflict` — a stale node or a misconfigured push can never overwrite a newer config.

---

### Option 1: Multiple Nameservers

The simplest setup. No load balancer required; the DNS protocol handles failover natively.

```
# /etc/resolv.conf on every client machine
nameserver 10.0.0.11
nameserver 10.0.0.12
nameserver 10.0.0.13
options timeout:1 attempts:3
```

The OS tries each nameserver in order on timeout. All nodes stay in sync through NanoDNS peer sync.

Best for: environments where DHCP or a config-management tool controls client DNS settings.

---

### Option 2: Keepalived Floating VIP

Active-Passive. Clients use a single virtual IP; Keepalived moves it when a node fails.

```
clients → 10.0.0.53 (virtual IP)

       ┌─── VRRP heartbeat ───┐
ns1 (MASTER)              ns2 (BACKUP)
 :53  :9053                :53  :9053
```

Install Keepalived:

```bash
apt install keepalived    # Debian / Ubuntu
yum install keepalived    # RHEL / CentOS
```

**`/etc/keepalived/keepalived.conf` on ns1:**

```
vrrp_script chk_nanodns {
    script   "/usr/bin/curl -sf http://127.0.0.1:9053/health"
    interval 2
    fall     2      # trigger failover after 2 consecutive failures
    rise     3      # recover after 3 consecutive successes
    weight   -20
}

vrrp_instance DNS_HA {
    state             MASTER
    interface         eth0
    virtual_router_id 53
    priority          100

    authentication {
        auth_type PASS
        auth_pass changeme
    }

    virtual_ipaddress {
        10.0.0.53/24
    }

    track_script {
        chk_nanodns
    }
}
```

On **ns2**: change `state MASTER` → `BACKUP` and `priority 100` → `80`. Everything else is identical.

Typical failover time: **4 seconds** (`interval × fall`).

---

### Option 3: HAProxy UDP Load Balancer

Active-Active. HAProxy distributes queries across all healthy nodes and removes unhealthy ones automatically. Requires **HAProxy 2.1+** for UDP support.

```bash
haproxy -v   # confirm version
```

**`haproxy.cfg`:**

```haproxy
frontend dns_in
    bind *:53 proto udp
    default_backend dns_nodes

backend dns_nodes
    balance    leastconn
    option     httpchk GET /health
    http-check expect status 200

    server ns1 10.0.0.11:53 check port 9053 inter 2s fall 2 rise 3 proto udp
    server ns2 10.0.0.12:53 check port 9053 inter 2s fall 2 rise 3 proto udp
    server ns3 10.0.0.13:53 check port 9053 inter 2s fall 2 rise 3 proto udp

frontend stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 5s
```

HAProxy health-checks each node's `/health` endpoint and removes it from rotation on failure. Config changes are propagated by calling `POST /reload` on any NanoDNS node.

---

### Option 4: Kubernetes

Kubernetes handles traffic availability through a Service and readiness probes. Use a ConfigMap for config; NanoDNS hot-reloads when the ConfigMap is updated.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nanodns
  namespace: dns
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate: { maxUnavailable: 1, maxSurge: 1 }
  selector:
    matchLabels: { app: nanodns }
  template:
    metadata:
      labels: { app: nanodns }
    spec:
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: DoNotSchedule
          labelSelector:
            matchLabels: { app: nanodns }
      containers:
        - name: nanodns
          image: ghcr.io/iyuangang/nanodns:latest
          args: ["start", "--config", "/etc/nanodns/nanodns.json"]
          ports:
            - { containerPort: 53,   protocol: UDP, name: dns  }
            - { containerPort: 9053, protocol: TCP, name: mgmt }
          volumeMounts:
            - { name: config, mountPath: /etc/nanodns }
          livenessProbe:
            httpGet: { path: /health, port: 9053 }
            periodSeconds: 5
            failureThreshold: 2
          readinessProbe:
            httpGet: { path: /ready, port: 9053 }
            periodSeconds: 3
          resources:
            requests: { cpu: 50m,  memory: 32Mi  }
            limits:   { cpu: 200m, memory: 128Mi }
      volumes:
        - name: config
          configMap: { name: nanodns-config }
---
apiVersion: v1
kind: Service
metadata:
  name: nanodns
  namespace: dns
spec:
  selector: { app: nanodns }
  type: LoadBalancer
  ports:
    - { name: dns,  port: 53,   protocol: UDP }
    - { name: mgmt, port: 9053, protocol: TCP }
```

To roll out a config change:

```bash
kubectl edit configmap nanodns-config -n dns
kubectl rollout restart deployment/nanodns -n dns
kubectl rollout status deployment/nanodns -n dns
```

---

### Option 5: Docker Compose Cluster

The repository ships a `docker-compose.yml` that starts a 3-node cluster with correct peer configuration, separate host ports, and a shared Docker network.

```bash
# Start all three nodes
docker compose up -d

# Check that all nodes are healthy and version-consistent
for p in 9053 9054 9055; do
  printf "port %s: " "$p"
  curl -s http://localhost:$p/health | \
    python3 -c "import sys, json; d = json.load(sys.stdin); print(d['status'], 'v' + str(d['version']))"
done
```

Nodes communicate over the `nanodns` Docker bridge network using container names as peer hostnames.

---

### Config Update Runbook

#### Normal update (any node)

```bash
# 1. Edit the config on any node
vim /etc/nanodns/nanodns.json

# 2. Reload — this atomically increments the version and pushes to all peers
curl -s -X POST http://127.0.0.1:9053/reload | python3 -m json.tool

# 3. Confirm all nodes converged
curl -s http://127.0.0.1:9053/cluster | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('self :', 'v' + str(d['self']['version']))
for addr, info in d['peers'].items():
    print(addr + ':', 'v' + str(info.get('version', '?')))
"
```

#### After a node restart

No manual steps required. Within 10 seconds the node catches up automatically:

```
[INFO] Catch-up: local v3 < peer 10.0.0.11:9053 v7 — pulling...
[INFO] Config persisted from peer sync  v7  checksum=a3f8b2c1 → /etc/nanodns/nanodns.json
[INFO] Config applied  v7  checksum=a3f8b2c1  (12 records  2 zones)
```

---

## Single-Node Deployment

### Linux systemd

```ini
# /etc/systemd/system/nanodns.service
[Unit]
Description=NanoDNS Server
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nanodns start --config /etc/nanodns/nanodns.json
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nanodns

[Install]
WantedBy=multi-user.target
```

```bash
sudo mkdir -p /etc/nanodns
sudo cp nanodns.json /etc/nanodns/
sudo systemctl daemon-reload
sudo systemctl enable --now nanodns
sudo journalctl -u nanodns -f
```

### Windows Service

Using [NSSM](https://nssm.cc/) — run PowerShell as Administrator:

```powershell
nssm install NanoDNS "C:\Python\Scripts\nanodns.exe"
nssm set NanoDNS AppParameters "start --config C:\dns\nanodns.json"
nssm set NanoDNS AppDirectory  "C:\dns"
nssm set NanoDNS DisplayName   "NanoDNS Server"
nssm set NanoDNS Start         SERVICE_AUTO_START
nssm start NanoDNS
```

Manage the service:

```powershell
nssm start   NanoDNS
nssm stop    NanoDNS
nssm restart NanoDNS
nssm remove  NanoDNS confirm
```

### Docker Single Node

```yaml
# docker-compose.yml
services:
  nanodns:
    image: ghcr.io/iyuangang/nanodns:latest
    container_name: nanodns
    restart: unless-stopped
    ports:
      - "53:53/udp"
      - "9053:9053/tcp"
    volumes:
      - ./nanodns.json:/etc/nanodns/nanodns.json
    cap_add: [NET_BIND_SERVICE]
```

```bash
docker compose up -d
docker compose logs -f
```

---

## Client Configuration

### Per-device

**Linux** — add to `/etc/resolv.conf`:
```
nameserver 10.0.0.11
```

**Windows** — Control Panel → Network and Sharing Center → Change adapter settings → IPv4 properties → Preferred DNS server.

**macOS** — System Settings → Network → Advanced → DNS tab.

### Via DHCP (recommended)

Set the DNS option on your router or DHCP server so all devices receive the NanoDNS address automatically. No per-device configuration needed.

**OpenWrt** (`/etc/config/dhcp`):

```
# Single node
option dns '10.0.0.11'

# HA cluster — send multiple nameservers to clients
list dns '10.0.0.11'
list dns '10.0.0.12'
list dns '10.0.0.13'
```

### High port + iptables (Linux, no root)

Run NanoDNS on port 5353 and redirect standard DNS traffic with iptables:

```bash
nanodns start --config nanodns.json --port 5353

sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
sudo iptables -t nat -A OUTPUT     -p udp --dport 53 -j REDIRECT --to-port 5353
```

---

## Testing and Verification

### dig

```bash
# Basic A record lookup
dig @127.0.0.1 -p 5353 web.internal.lan A

# MX records
dig @127.0.0.1 -p 5353 internal.lan MX

# SOA record
dig @127.0.0.1 -p 5353 internal.lan SOA

# Confirm a blocked domain returns NXDOMAIN
dig @127.0.0.1 -p 5353 blocked.example.com

# Wildcard
dig @127.0.0.1 -p 5353 anything.app.internal.lan A
```

### nslookup

```bash
nslookup web.internal.lan 127.0.0.1
```

### PowerShell

```powershell
Resolve-DnsName -Name web.internal.lan -Server 127.0.0.1 -Type A
```

### HA cluster checks

```bash
# Confirm all nodes report the same config version
for node in 10.0.0.11 10.0.0.12 10.0.0.13; do
  v=$(curl -s http://$node:9053/metrics \
    | python3 -c "import sys, json; print(json.load(sys.stdin)['version'])")
  echo "$node  v$v"
done

# Failover test — stop one node and confirm queries still succeed
sudo systemctl stop nanodns                  # on ns1
dig @10.0.0.53 web.internal.lan A            # VIP should still respond

# Catch-up test — restart the stopped node and verify it converges
sudo systemctl start nanodns
sleep 15
curl -s http://10.0.0.11:9053/metrics \
  | python3 -c "import sys, json; d = json.load(sys.stdin); print('version:', d['version'])"
```

---

## FAQ

**Port 53 gives "permission denied".**

Run on a high port for development (`--port 5353`). In production use `sudo`, a systemd service unit (which runs as root), or grant the binary the `CAP_NET_BIND_SERVICE` capability.

---

**I edited the config but nothing changed.**

Check that `hot_reload: true` in your config — the server polls for changes every 5 seconds. For an immediate reload:

```bash
curl -X POST http://localhost:9053/reload
```

If `mgmt_port` is `0`, restart the process instead.

---

**Nodes have different configs after a sync failure.**

```bash
# 1. Check the cluster state
curl http://localhost:9053/cluster | python3 -m json.tool

# 2. Check logs on the lagging node
sudo journalctl -u nanodns -n 50

# 3. Restart the lagging node — it catches up within 10 seconds automatically
sudo systemctl restart nanodns

# 4. Alternatively, trigger a fresh push from the most up-to-date node
curl -X POST http://10.0.0.11:9053/reload
```

---

**External names fail to resolve but internal names work.**

The upstream resolvers are unreachable. Test directly:

```bash
dig @8.8.8.8 google.com
```

If the server has no public internet access, point `upstream` at a resolver that is reachable from your network:

```json
"upstream": ["119.29.29.29", "223.5.5.5"]
```

Also check that UDP port 53 outbound is allowed by your firewall.

---

**I have two A records for the same name. Will they load-balance?**

Yes. Both records are included in every response. Most operating-system resolvers and applications rotate through them automatically (round-robin DNS).

---

**Do I need to update `config_version` manually?**

No — never. `config_version` is incremented automatically on every `POST /reload`, and peers receive the version as part of the push payload. Editing `config_version` by hand will corrupt the sync ordering.

---

**How do I configure `peers` for a 3-node cluster?**

Each node lists the management addresses of the *other* nodes:

| Node | `peers` value |
|------|---------------|
| ns1 `10.0.0.11` | `["10.0.0.12:9053", "10.0.0.13:9053"]` |
| ns2 `10.0.0.12` | `["10.0.0.11:9053", "10.0.0.13:9053"]` |
| ns3 `10.0.0.13` | `["10.0.0.11:9053", "10.0.0.12:9053"]` |

A reload on any node will push to the other two.

---

**I'm seeing lots of SERVFAIL responses.**

All configured upstream resolvers are failing. Checklist:

1. Are the IP addresses in `upstream` correct?
2. Can the server reach them? (`dig @8.8.8.8 google.com` from the server)
3. Is UDP port 53 outbound permitted by the firewall?
4. Are the upstreams slow but reachable? Increase `upstream_timeout`.
