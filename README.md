# NanoDNS

A lightweight, zero-dependency DNS server for internal networks — configured with a single JSON file.

## Features

- 🚀 **Zero dependencies** — pure Python standard library only
- 📝 **JSON config** — human-readable, hot-reloadable configuration
- 🔄 **Upstream forwarding** — forwards unknown queries to public DNS
- 💾 **LRU Cache** — configurable in-memory response cache
- 🌐 **Record types** — A, AAAA, CNAME, MX, TXT, PTR, NS, SOA
- 🃏 **Wildcard records** — `*.example.internal` support
- 🚫 **Rewrites / blocking** — NXDOMAIN any domain
- ♻️ **Hot reload** — config changes applied without restart
- ⚡ **Async** — built on Python asyncio

## Installation

```bash
pip install nanodns-server
```

## Quick Start

```bash
# 1. Generate an example config
nanodns init

# 2. Edit nanodns.json to your needs

# 3. Start the server (port 53 needs root, or use port 5353)
sudo nanodns start --config nanodns.json

# Or on a high port for testing:
nanodns start --config nanodns.json --port 5353
```

## Configuration

```jsonc
{
  "server": {
    "host": "0.0.0.0",          // Listen address
    "port": 53,                  // Listen port
    "upstream": ["8.8.8.8", "1.1.1.1"],  // Fallback DNS servers
    "upstream_timeout": 3,       // Seconds before trying next upstream
    "upstream_port": 53,
    "cache_enabled": true,
    "cache_ttl": 300,            // Max TTL to cache (seconds)
    "cache_size": 1000,          // Max cached entries
    "log_level": "INFO",         // DEBUG | INFO | WARNING | ERROR
    "log_queries": true,         // Log every query
    "hot_reload": true           // Watch config file for changes
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
    { "name": "web.internal.lan",  "type": "A",     "value": "192.168.1.100", "ttl": 300 },
    { "name": "db.internal.lan",   "type": "A",     "value": "192.168.1.101", "ttl": 300 },
    { "name": "api.internal.lan",  "type": "CNAME", "value": "web.internal.lan" },
    { "name": "internal.lan",      "type": "MX",    "value": "mail.internal.lan", "priority": 10 },
    { "name": "internal.lan",      "type": "TXT",   "value": "v=spf1 ip4:192.168.1.0/24 ~all" },
    { "name": "ipv6.internal.lan", "type": "AAAA",  "value": "fd00::1" },
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

## CLI Reference

```
nanodns start [--config FILE] [--host HOST] [--port PORT] [--log-level LEVEL] [--no-cache]
nanodns init  [OUTPUT]        # Generate example config
nanodns check CONFIG          # Validate a config file
nanodns --version
```

## Record Types

| Type  | `value` field          | Extra fields     |
|-------|------------------------|------------------|
| A     | IPv4 address           | —                |
| AAAA  | IPv6 address           | —                |
| CNAME | Target hostname        | —                |
| MX    | Mail server hostname   | `priority` (int) |
| TXT   | Text string            | —                |
| PTR   | Pointer hostname       | —                |
| NS    | Nameserver hostname    | —                |

All records support: `ttl` (default 300), `wildcard` (bool), `comment` (string).

## Running as a Service (systemd)

```ini
# /etc/systemd/system/nanodns.service
[Unit]
Description=NanoDNS Server
After=network.target

[Service]
ExecStart=/usr/local/bin/nanodns start --config /etc/nanodns/nanodns.json
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now nanodns
```

## High Port (No Root Required)

```bash
nanodns start --config nanodns.json --port 5353
```

Then configure clients to use `<server-ip>:5353`, or use iptables to redirect:

```bash
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
```

## Testing

```bash
# Query your local server
dig @127.0.0.1 -p 5353 web.internal.lan A

# With nslookup
nslookup web.internal.lan 127.0.0.1
```

## License

MIT
