"""
Unit and integration tests for NanoDNS HA config-sync machinery.
Covers: version bumping, push (POST /sync) with anti-rollback,
        catch-up pull (GET /config/raw), cluster status endpoint,
        full push-to-peers flow.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nanodns.config import (
    _parse_config, load_config, load_config_from_bytes, bump_version,
)
from nanodns.cache import DNSCache
from nanodns.handler import DNSHandler
from nanodns.mgmt import MgmtServer, _probe_peer_health, _push_sync, _fetch_raw_config
from nanodns.server import DNSServer, _set_version


# ═══════════════════════════════════════════════════════════════════════════════
# Shared helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _raw(version: int = 1, records: list = None, peers: list = None) -> bytes:
    """Build a minimal config payload with the given version."""
    return json.dumps({
        "server": {
            "host": "127.0.0.1", "port": 55353,
            "upstream": [], "upstream_timeout": 1, "upstream_port": 53,
            "cache_enabled": False, "cache_ttl": 60, "cache_size": 100,
            "log_level": "WARNING", "log_queries": False, "hot_reload": False,
            "mgmt_host": "127.0.0.1", "mgmt_port": 0,
            "peers": peers or [],
            "config_version": version,
        },
        "zones": {},
        "records": records or [],
        "rewrites": [],
    }, indent=2).encode()


def _fake_server(raw: bytes, config_path: Path = None) -> DNSServer:
    """Build a DNSServer without binding any real UDP socket."""
    cfg = load_config_from_bytes(raw, config_path)
    srv = object.__new__(DNSServer)
    srv.config     = cfg
    srv.cache      = DNSCache(max_size=10)
    srv.handler    = DNSHandler(cfg, srv.cache)
    srv._transport = None
    srv._running   = True
    srv._mgmt      = None
    original_apply = DNSServer.apply_config
    srv.apply_config = lambda new_cfg: original_apply(srv, new_cfg)
    srv.cache_stats  = lambda: srv.cache.stats
    return srv


def _wait(url: str, timeout: float = 3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return
        except Exception:
            time.sleep(0.05)
    raise RuntimeError(f"Timed out waiting for {url}")


# ═══════════════════════════════════════════════════════════════════════════════
# Config versioning — pure unit tests (no network)
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfigVersioning:

    def test_version_round_trips(self):
        assert load_config_from_bytes(_raw(version=7)).version == 7

    def test_bump_increments_by_one(self):
        assert load_config_from_bytes(bump_version(_raw(version=3))).version == 4

    def test_set_version_to_arbitrary_value(self):
        assert load_config_from_bytes(_set_version(_raw(version=1), 99)).version == 99

    def test_checksum_stable_for_same_content(self):
        r = _raw(version=5)
        assert load_config_from_bytes(r).checksum == load_config_from_bytes(r).checksum

    def test_checksum_changes_with_content(self):
        c1 = load_config_from_bytes(_raw(version=1))
        c2 = load_config_from_bytes(_raw(version=1, records=[
            {"name": "x.test", "type": "A", "value": "1.2.3.4"}
        ]))
        assert c1.checksum != c2.checksum

    def test_load_from_bytes_persists_to_disk(self, tmp_path):
        p   = tmp_path / "nd.json"
        raw = _raw(version=2)
        cfg = load_config_from_bytes(raw, p)
        assert p.exists()
        assert p.read_bytes() == raw
        assert cfg.version == 2


# ═══════════════════════════════════════════════════════════════════════════════
# Management HTTP endpoints
# ═══════════════════════════════════════════════════════════════════════════════

class TestMgmtEndpoints:

    def test_health_and_ready(self):
        srv  = _fake_server(_raw(version=1))
        mgmt = MgmtServer("127.0.0.1", 19200)
        mgmt.start(srv)
        try:
            _wait("http://127.0.0.1:19200/health")
            h = json.loads(urllib.request.urlopen(
                "http://127.0.0.1:19200/health").read())
            assert h["status"] == "ok" and h["version"] == 1
            r = json.loads(urllib.request.urlopen(
                "http://127.0.0.1:19200/ready").read())
            assert r["status"] == "ready"
        finally:
            mgmt.stop()

    def test_config_raw_returns_current_bytes(self):
        raw  = _raw(version=3)
        srv  = _fake_server(raw)
        mgmt = MgmtServer("127.0.0.1", 19201)
        mgmt.start(srv)
        try:
            _wait("http://127.0.0.1:19201/health")
            fetched = _fetch_raw_config("127.0.0.1:19201")
            assert fetched is not None
            assert json.loads(fetched)["server"]["config_version"] == 3
        finally:
            mgmt.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# Config sync — push (POST /sync)
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfigSync:

    def test_newer_version_applied(self, tmp_path):
        p    = tmp_path / "nd.json"
        srv  = _fake_server(_raw(version=1), p)
        mgmt = MgmtServer("127.0.0.1", 19202)
        mgmt.start(srv)
        try:
            _wait("http://127.0.0.1:19202/health")
            new_raw = _raw(version=2, records=[
                {"name": "pushed.test", "type": "A", "value": "9.9.9.9"}
            ])
            result = _push_sync("127.0.0.1:19202", new_raw)
            assert result["status"] == "applied"
            assert result["version"] == 2
            assert srv.config.version == 2
            assert srv.config.records[0].name == "pushed.test"
            assert json.loads(p.read_bytes())["server"]["config_version"] == 2
        finally:
            mgmt.stop()

    def test_same_version_is_idempotent(self):
        srv  = _fake_server(_raw(version=2))
        mgmt = MgmtServer("127.0.0.1", 19203)
        mgmt.start(srv)
        try:
            _wait("http://127.0.0.1:19203/health")
            new_raw = _raw(version=3)
            assert _push_sync("127.0.0.1:19203", new_raw)["status"] == "applied"
            assert _push_sync("127.0.0.1:19203", new_raw)["status"] == "already_current"
        finally:
            mgmt.stop()

    def test_stale_version_rejected(self):
        """Anti-rollback: pushing an older version must be rejected."""
        srv  = _fake_server(_raw(version=5))
        mgmt = MgmtServer("127.0.0.1", 19204)
        mgmt.start(srv)
        try:
            _wait("http://127.0.0.1:19204/health")
            stale = _raw(version=1)
            try:
                result = _push_sync("127.0.0.1:19204", stale)
            except urllib.error.HTTPError as exc:
                result = json.loads(exc.read())
            assert (result.get("status") == "rejected_stale"
                    or result.get("http_error") == 409), result
            assert srv.config.version == 5, "version must not have rolled back"
        finally:
            mgmt.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# Catch-up pull — offline nodes
# ═══════════════════════════════════════════════════════════════════════════════

class TestCatchUp:

    def test_node_catches_up_from_peer(self, tmp_path):
        """Node A (v1) must pull v5 from Node B when catchup_from_peers() runs."""
        p_b   = tmp_path / "b.json"
        srv_b = _fake_server(_raw(version=5), p_b)
        mgmt_b = MgmtServer("127.0.0.1", 19205)
        mgmt_b.start(srv_b)

        p_a   = tmp_path / "a.json"
        srv_a = _fake_server(_raw(version=1, peers=["127.0.0.1:19205"]), p_a)
        mgmt_a = MgmtServer("127.0.0.1", 19206)
        mgmt_a.start(srv_a)
        try:
            _wait("http://127.0.0.1:19205/health")
            _wait("http://127.0.0.1:19206/health")
            result = mgmt_a.catchup_from_peers()
            assert result is not None
            assert result["version"] == 5
            assert srv_a.config.version == 5
            assert json.loads(p_a.read_bytes())["server"]["config_version"] == 5
        finally:
            mgmt_a.stop()
            mgmt_b.stop()

    def test_no_catchup_when_already_ahead(self):
        """Node at v10 should not pull from a peer at v5."""
        srv_b  = _fake_server(_raw(version=5))
        mgmt_b = MgmtServer("127.0.0.1", 19207)
        mgmt_b.start(srv_b)

        srv_a  = _fake_server(_raw(version=10, peers=["127.0.0.1:19207"]))
        mgmt_a = MgmtServer("127.0.0.1", 19208)
        mgmt_a.start(srv_a)
        try:
            _wait("http://127.0.0.1:19207/health")
            _wait("http://127.0.0.1:19208/health")
            assert mgmt_a.catchup_from_peers() is None
            assert srv_a.config.version == 10
        finally:
            mgmt_a.stop()
            mgmt_b.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# Cluster status
# ═══════════════════════════════════════════════════════════════════════════════

class TestClusterStatus:

    def test_cluster_endpoint_shows_peer_health(self):
        srv_b  = _fake_server(_raw(version=4))
        mgmt_b = MgmtServer("127.0.0.1", 19209)
        mgmt_b.start(srv_b)

        srv_a  = _fake_server(_raw(version=4, peers=["127.0.0.1:19209"]))
        mgmt_a = MgmtServer("127.0.0.1", 19210)
        mgmt_a.start(srv_a)
        try:
            _wait("http://127.0.0.1:19209/health")
            _wait("http://127.0.0.1:19210/health")
            cluster = json.loads(
                urllib.request.urlopen("http://127.0.0.1:19210/cluster").read()
            )
            assert cluster["self"]["status"]  == "ok"
            assert cluster["self"]["version"] == 4
            peer = cluster["peers"].get("127.0.0.1:19209", {})
            assert peer.get("reachable") is True
            assert peer.get("version")   == 4
        finally:
            mgmt_a.stop()
            mgmt_b.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# Full push-to-peers flow
# ═══════════════════════════════════════════════════════════════════════════════

class TestPushToPeers:

    def test_reload_on_primary_propagates_to_all_peers(self, tmp_path):
        """v2 config pushed from A must be applied on both B and C."""
        p_b, p_c = tmp_path / "b.json", tmp_path / "c.json"

        srv_b  = _fake_server(_raw(version=1), p_b)
        mgmt_b = MgmtServer("127.0.0.1", 19211)
        mgmt_b.start(srv_b)

        srv_c  = _fake_server(_raw(version=1), p_c)
        mgmt_c = MgmtServer("127.0.0.1", 19212)
        mgmt_c.start(srv_c)

        raw_a2 = _raw(
            version=2,
            records=[{"name": "new.test", "type": "A", "value": "1.2.3.4"}],
            peers=["127.0.0.1:19211", "127.0.0.1:19212"],
        )
        srv_a  = _fake_server(raw_a2)
        mgmt_a = MgmtServer("127.0.0.1", 19213)
        mgmt_a.start(srv_a)
        try:
            _wait("http://127.0.0.1:19211/health")
            _wait("http://127.0.0.1:19212/health")
            _wait("http://127.0.0.1:19213/health")
            results = mgmt_a.push_to_peers(srv_a.config)
            assert results["127.0.0.1:19211"]["status"] == "applied"
            assert results["127.0.0.1:19212"]["status"] == "applied"
            for srv in (srv_b, srv_c):
                assert srv.config.version == 2
                assert srv.config.records[0].name == "new.test"
        finally:
            mgmt_a.stop()
            mgmt_b.stop()
            mgmt_c.stop()
