"""
Configuration loader for NanoDNS.
Supports JSON config files with hot-reload and peer-sync capability.

Versioning model
────────────────
Every time a config is written to disk it gets a monotonically-increasing
integer `config_version` embedded in the JSON under server.config_version.

  • First-ever write: version = 1
  • Each reload/edit:  version = old_version + 1

The version is the *only* source of truth for "who is newer".  Checksums
are used purely for idempotency (skip re-applying identical bytes); they
do NOT determine ordering.

This lets a node that was offline catch up: on start it queries all peers
for their version, and if any peer is ahead it pulls the config from that
peer via GET /config/raw.
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── default / example configs ─────────────────────────────────────────────────

DEFAULT_CONFIG: dict = {
    "server": {
        "host": "0.0.0.0",
        "port": 53,
        "upstream": ["8.8.8.8", "1.1.1.1"],
        "upstream_timeout": 3,
        "upstream_port": 53,
        "cache_enabled": True,
        "cache_ttl": 300,
        "cache_size": 1000,
        "log_level": "INFO",
        "log_queries": True,
        "hot_reload": True,
        "mgmt_host": "0.0.0.0",
        "mgmt_port": 9053,
        "peers": [],
        "config_version": 1,
    },
    "zones": {},
    "records": [],
    "rewrites": [],
}

EXAMPLE_CONFIG: dict = {
    "server": {
        "host": "0.0.0.0",
        "port": 53,
        "upstream": ["8.8.8.8", "1.1.1.1"],
        "upstream_timeout": 3,
        "upstream_port": 53,
        "cache_enabled": True,
        "cache_ttl": 300,
        "cache_size": 1000,
        "log_level": "INFO",
        "log_queries": True,
        "hot_reload": True,
        "mgmt_host": "0.0.0.0",
        "mgmt_port": 9053,
        # List the mgmt address (host:port) of every other node in the cluster.
        # Each node will push config changes to its peers and pull from them
        # on startup if it finds it is behind.
        # Example 3-node cluster:  ["10.0.0.12:9053", "10.0.0.13:9053"]
        "peers": [],
        # Auto-managed — do not edit by hand.
        "config_version": 1,
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
                "minimum": 300,
            },
            "ns": ["ns1.internal.lan"],
        }
    },
    "records": [
        {"name": "ns1.internal.lan",      "type": "A",     "value": "192.168.1.10",  "ttl": 3600},
        {"name": "web.internal.lan",      "type": "A",     "value": "192.168.1.100", "ttl": 300,
         "comment": "Internal web server"},
        {"name": "db.internal.lan",       "type": "A",     "value": "192.168.1.101", "ttl": 300},
        {"name": "api.internal.lan",      "type": "CNAME", "value": "web.internal.lan", "ttl": 300},
        {"name": "internal.lan",          "type": "MX",    "value": "mail.internal.lan",
         "priority": 10, "ttl": 3600},
        {"name": "internal.lan",          "type": "TXT",
         "value": "v=spf1 ip4:192.168.1.0/24 ~all", "ttl": 3600},
        {"name": "ipv6host.internal.lan", "type": "AAAA",  "value": "fd00::1", "ttl": 300},
        {"name": "wildcard.internal.lan", "type": "A",     "value": "192.168.1.200",
         "ttl": 300, "wildcard": True, "comment": "Matches *.wildcard.internal.lan"},
    ],
    "rewrites": [
        {"match": "blocked.example.com", "action": "nxdomain", "comment": "Block this domain"},
        {"match": "*.ads.example.com",   "action": "nxdomain"},
    ],
}


# ── dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 53
    upstream: list[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    upstream_timeout: int = 3
    upstream_port: int = 53
    cache_enabled: bool = True
    cache_ttl: int = 300
    cache_size: int = 1000
    log_level: str = "INFO"
    log_queries: bool = True
    hot_reload: bool = True
    # ── HA fields ─────────────────────────────────────────────────────────────
    # Management HTTP server.  Set mgmt_port > 0 to enable (e.g. 9053).
    mgmt_host: str = "0.0.0.0"
    mgmt_port: int = 0
    # Peer mgmt addresses for config-sync.  Format: "host:port".
    # A node pushes its config to all peers on reload and pulls from peers
    # that are ahead on startup.
    peers: list[str] = field(default_factory=list)
    # Monotonic config version — auto-incremented on every write.
    # Drives catch-up: a node with a lower version pulls from the higher one.
    config_version: int = 1


@dataclass
class ZoneSOA:
    mname: str
    rname: str
    serial: int = 2024010101
    refresh: int = 3600
    retry: int = 900
    expire: int = 604800
    minimum: int = 300


@dataclass
class ZoneConfig:
    soa: Optional[ZoneSOA] = None
    ns: list[str] = field(default_factory=list)


@dataclass
class RecordEntry:
    name: str
    rtype: str
    value: str
    ttl: int = 300
    priority: int = 10
    wildcard: bool = False
    comment: str = ""


@dataclass
class RewriteEntry:
    match: str
    action: str          # nxdomain | redirect
    value: str = ""
    comment: str = ""
    is_wildcard: bool = False


@dataclass
class Config:
    server: ServerConfig = field(default_factory=ServerConfig)
    zones: dict[str, ZoneConfig] = field(default_factory=dict)
    records: list[RecordEntry] = field(default_factory=list)
    rewrites: list[RewriteEntry] = field(default_factory=list)
    _path: Optional[Path] = field(default=None, repr=False)
    _mtime: float = field(default=0.0, repr=False)
    # Raw JSON bytes kept for peer push — we push exactly what we loaded so
    # every peer writes the same bytes and derives the same checksum.
    _raw: bytes = field(default=b"", repr=False)

    # ── record / rewrite lookup ───────────────────────────────────────────────

    def get_records(self, name: str, rtype: str) -> list[RecordEntry]:
        name = name.rstrip(".").lower()
        results = []
        for rec in self.records:
            rname = rec.name.rstrip(".").lower()
            if rec.rtype.upper() != rtype.upper():
                continue
            if rname == name:
                results.append(rec)
            elif rec.wildcard:
                suffix = "." + rname
                if name.endswith(suffix) and "." not in name[: -len(suffix)]:
                    results.append(rec)
        return results

    def get_rewrite(self, name: str) -> Optional[RewriteEntry]:
        name = name.rstrip(".").lower()
        for rw in self.rewrites:
            if rw.is_wildcard:
                suffix = "." + rw.match.lstrip("*.").lower()
                if name.endswith(suffix):
                    return rw
            else:
                if name == rw.match.lower():
                    return rw
        return None

    # ── hot-reload staleness ──────────────────────────────────────────────────

    def is_stale(self) -> bool:
        if not self._path or not self.server.hot_reload:
            return False
        try:
            return self._path.stat().st_mtime != self._mtime
        except OSError:
            return False

    # ── identity helpers ──────────────────────────────────────────────────────

    @property
    def version(self) -> int:
        """The monotonic config_version embedded in the server section."""
        return self.server.config_version

    @property
    def checksum(self) -> str:
        """SHA-256 of raw bytes, first 16 hex chars.  Used for idempotency only."""
        if not self._raw:
            return ""
        return hashlib.sha256(self._raw).hexdigest()[:16]


# ── loaders ───────────────────────────────────────────────────────────────────

def load_config(path: Optional[str] = None) -> Config:
    """Load configuration from a JSON file.  Uses built-in defaults if no path."""
    if path is None:
        return _parse_config(DEFAULT_CONFIG, None, b"")

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = p.read_bytes()
    data = json.loads(raw)
    config = _parse_config(data, p, raw)
    config._mtime = p.stat().st_mtime
    logger.info(
        "Loaded config from %s  (v%d  %d records  %d zones  checksum=%s)",
        p, config.version, len(config.records), len(config.zones), config.checksum,
    )
    return config


def load_config_from_bytes(raw: bytes, existing_path: Optional[Path] = None) -> Config:
    """Parse config from raw JSON bytes (used for peer-sync push/pull).

    If *existing_path* is given the bytes are persisted to disk so the
    file-watcher stays in sync and the config survives a restart.

    The caller is responsible for bumping config_version before calling this
    (i.e. the version must already be correct inside *raw*).
    """
    data = json.loads(raw)
    config = _parse_config(data, existing_path, raw)
    if existing_path:
        existing_path.parent.mkdir(parents=True, exist_ok=True)
        existing_path.write_bytes(raw)
        config._mtime = existing_path.stat().st_mtime
        logger.info(
            "Config persisted from peer sync  v%d  checksum=%s → %s",
            config.version, config.checksum, existing_path,
        )
    return config


def bump_version(raw: bytes) -> bytes:
    """Return *raw* with server.config_version incremented by 1.

    Called before pushing a locally-reloaded config to peers so every
    write to disk carries a strictly higher version number.
    """
    data = json.loads(raw)
    old = data.setdefault("server", {}).get("config_version", 1)
    data["server"]["config_version"] = old + 1
    return json.dumps(data, indent=2, ensure_ascii=False).encode()


def _parse_config(data: dict, path: Optional[Path], raw: bytes = b"") -> Config:
    sd = data.get("server", {})
    server = ServerConfig(
        host=sd.get("host", "0.0.0.0"),
        port=sd.get("port", 53),
        upstream=sd.get("upstream", ["8.8.8.8", "1.1.1.1"]),
        upstream_timeout=sd.get("upstream_timeout", 3),
        upstream_port=sd.get("upstream_port", 53),
        cache_enabled=sd.get("cache_enabled", True),
        cache_ttl=sd.get("cache_ttl", 300),
        cache_size=sd.get("cache_size", 1000),
        log_level=sd.get("log_level", "INFO"),
        log_queries=sd.get("log_queries", True),
        hot_reload=sd.get("hot_reload", True),
        mgmt_host=sd.get("mgmt_host", "0.0.0.0"),
        mgmt_port=sd.get("mgmt_port", 0),
        peers=sd.get("peers", []),
        config_version=sd.get("config_version", 1),
    )

    zones: dict[str, ZoneConfig] = {}
    for zone_name, zone_data in data.get("zones", {}).items():
        soa = None
        if "soa" in zone_data:
            s = zone_data["soa"]
            soa = ZoneSOA(
                mname=s.get("mname", f"ns1.{zone_name}"),
                rname=s.get("rname", f"admin.{zone_name}"),
                serial=s.get("serial", 2024010101),
                refresh=s.get("refresh", 3600),
                retry=s.get("retry", 900),
                expire=s.get("expire", 604800),
                minimum=s.get("minimum", 300),
            )
        zones[zone_name] = ZoneConfig(soa=soa, ns=zone_data.get("ns", []))

    records: list[RecordEntry] = [
        RecordEntry(
            name=r["name"], rtype=r["type"], value=r["value"],
            ttl=r.get("ttl", 300), priority=r.get("priority", 10),
            wildcard=r.get("wildcard", False), comment=r.get("comment", ""),
        )
        for r in data.get("records", [])
    ]

    rewrites: list[RewriteEntry] = []
    for rw in data.get("rewrites", []):
        m = rw["match"]
        rewrites.append(RewriteEntry(
            match=m, action=rw["action"],
            value=rw.get("value", ""), comment=rw.get("comment", ""),
            is_wildcard=m.startswith("*."),
        ))

    return Config(
        server=server, zones=zones, records=records, rewrites=rewrites,
        _path=path, _raw=raw,
    )


def generate_example_config(path: str) -> None:
    with open(path, "w") as f:
        json.dump(EXAMPLE_CONFIG, f, indent=2)
    print(f"Example config written to: {path}")
