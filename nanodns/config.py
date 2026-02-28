"""
Configuration loader for NanoDNS.
Supports JSON config files with hot-reload capability.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
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
        "hot_reload": True
    },
    "zones": {},
    "records": []
}

EXAMPLE_CONFIG = {
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
        "hot_reload": True
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
        {
            "name": "ns1.internal.lan",
            "type": "A",
            "value": "192.168.1.10",
            "ttl": 3600
        },
        {
            "name": "web.internal.lan",
            "type": "A",
            "value": "192.168.1.100",
            "ttl": 300,
            "comment": "Internal web server"
        },
        {
            "name": "db.internal.lan",
            "type": "A",
            "value": "192.168.1.101",
            "ttl": 300
        },
        {
            "name": "api.internal.lan",
            "type": "CNAME",
            "value": "web.internal.lan",
            "ttl": 300
        },
        {
            "name": "internal.lan",
            "type": "MX",
            "value": "mail.internal.lan",
            "priority": 10,
            "ttl": 3600
        },
        {
            "name": "internal.lan",
            "type": "TXT",
            "value": "v=spf1 ip4:192.168.1.0/24 ~all",
            "ttl": 3600
        },
        {
            "name": "ipv6host.internal.lan",
            "type": "AAAA",
            "value": "fd00::1",
            "ttl": 300
        },
        {
            "name": "wildcard.internal.lan",
            "type": "A",
            "value": "192.168.1.200",
            "ttl": 300,
            "wildcard": True,
            "comment": "Wildcard: matches *.wildcard.internal.lan"
        }
    ],
    "rewrites": [
        {
            "match": "blocked.example.com",
            "action": "nxdomain",
            "comment": "Block this domain"
        },
        {
            "match": "*.ads.example.com",
            "action": "nxdomain"
        }
    ]
}


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
    priority: int = 10   # for MX
    wildcard: bool = False
    comment: str = ""


@dataclass
class RewriteEntry:
    match: str
    action: str  # nxdomain | redirect
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

    def get_records(self, name: str, rtype: str) -> list[RecordEntry]:
        """Return all records matching the given name and type."""
        name = name.rstrip(".").lower()
        results = []
        for rec in self.records:
            rname = rec.name.rstrip(".").lower()
            if rec.rtype.upper() != rtype.upper():
                continue
            if rname == name:
                results.append(rec)
            elif rec.wildcard:
                # *.foo.bar matches anything.foo.bar
                suffix = "." + rname
                if name.endswith(suffix) and "." not in name[: -len(suffix)]:
                    results.append(rec)
        return results

    def get_rewrite(self, name: str) -> Optional[RewriteEntry]:
        """Return the first matching rewrite rule."""
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

    def is_stale(self) -> bool:
        if not self._path or not self.server.hot_reload:
            return False
        try:
            mtime = self._path.stat().st_mtime
            return mtime != self._mtime
        except OSError:
            return False


def load_config(path: Optional[str] = None) -> Config:
    """Load configuration from a JSON file. Uses defaults if no path given."""
    if path is None:
        return _parse_config(DEFAULT_CONFIG, None)

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(p) as f:
        data = json.load(f)

    config = _parse_config(data, p)
    config._mtime = p.stat().st_mtime
    logger.info(f"Loaded config from {p} ({len(config.records)} records, {len(config.zones)} zones)")
    return config


def _parse_config(data: dict, path: Optional[Path]) -> Config:
    server_data = data.get("server", {})
    server = ServerConfig(
        host=server_data.get("host", "0.0.0.0"),
        port=server_data.get("port", 53),
        upstream=server_data.get("upstream", ["8.8.8.8", "1.1.1.1"]),
        upstream_timeout=server_data.get("upstream_timeout", 3),
        upstream_port=server_data.get("upstream_port", 53),
        cache_enabled=server_data.get("cache_enabled", True),
        cache_ttl=server_data.get("cache_ttl", 300),
        cache_size=server_data.get("cache_size", 1000),
        log_level=server_data.get("log_level", "INFO"),
        log_queries=server_data.get("log_queries", True),
        hot_reload=server_data.get("hot_reload", True),
    )

    zones: dict[str, ZoneConfig] = {}
    for zone_name, zone_data in data.get("zones", {}).items():
        soa = None
        if "soa" in zone_data:
            sd = zone_data["soa"]
            soa = ZoneSOA(
                mname=sd.get("mname", f"ns1.{zone_name}"),
                rname=sd.get("rname", f"admin.{zone_name}"),
                serial=sd.get("serial", 2024010101),
                refresh=sd.get("refresh", 3600),
                retry=sd.get("retry", 900),
                expire=sd.get("expire", 604800),
                minimum=sd.get("minimum", 300),
            )
        zones[zone_name] = ZoneConfig(soa=soa, ns=zone_data.get("ns", []))

    records: list[RecordEntry] = []
    for rec in data.get("records", []):
        records.append(
            RecordEntry(
                name=rec["name"],
                rtype=rec["type"],
                value=rec["value"],
                ttl=rec.get("ttl", 300),
                priority=rec.get("priority", 10),
                wildcard=rec.get("wildcard", False),
                comment=rec.get("comment", ""),
            )
        )

    rewrites: list[RewriteEntry] = []
    for rw in data.get("rewrites", []):
        match = rw["match"]
        is_wildcard = match.startswith("*.")
        rewrites.append(
            RewriteEntry(
                match=match,
                action=rw["action"],
                value=rw.get("value", ""),
                comment=rw.get("comment", ""),
                is_wildcard=is_wildcard,
            )
        )

    config = Config(server=server, zones=zones, records=records, rewrites=rewrites, _path=path)
    return config


def generate_example_config(path: str):
    """Write an example config file."""
    with open(path, "w") as f:
        json.dump(EXAMPLE_CONFIG, f, indent=2)
    print(f"Example config written to: {path}")
