"""
Tests for NanoDNS HA config-sync machinery.

Covers the full stack:
  - version bumping
  - push (POST /sync) with anti-rollback
  - catch-up pull (GET /config/raw)
  - reconcile_peers integration
  - cluster status endpoint
"""

import json
import os
import sys
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


from nanodns.config import (
    Config, ServerConfig, _parse_config,
    load_config, load_config_from_bytes, bump_version,
)
from nanodns.cache import DNSCache
from nanodns.handler import DNSHandler
from nanodns.mgmt import MgmtServer, _probe_peer_health, _push_sync, _fetch_raw_config
from nanodns.server import DNSServer, _set_version


# ── test fixtures ─────────────────────────────────────────────────────────────

def _raw(version: int = 1, records: list = None, peers: list = None) -> bytes:
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
    """Build a DNSServer-like object without binding any real UDP socket."""
    cfg = load_config_from_bytes(raw, config_path)
    srv = object.__new__(DNSServer)
    srv.config   = cfg
    srv.cache    = DNSCache(max_size=10)
    srv.handler  = DNSHandler(cfg, srv.cache)
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


# ── unit tests ────────────────────────────────────────────────────────────────

def test_version_in_raw():
    r = _raw(version=7)
    cfg = load_config_from_bytes(r)
    assert cfg.version == 7

def test_bump_version():
    r  = _raw(version=3)
    r2 = bump_version(r)
    assert load_config_from_bytes(r2).version == 4

def test_set_version():
    r  = _raw(version=1)
    r2 = _set_version(r, 99)
    assert load_config_from_bytes(r2).version == 99

def test_checksum_stable():
    r = _raw(version=5)
    assert load_config_from_bytes(r).checksum == load_config_from_bytes(r).checksum

def test_checksum_changes_with_content():
    c1 = load_config_from_bytes(_raw(version=1))
    c2 = load_config_from_bytes(_raw(version=1, records=[
        {"name": "x.test", "type": "A", "value": "1.2.3.4"}
    ]))
    assert c1.checksum != c2.checksum

def test_load_from_bytes_persists(tmp_path):
    p   = tmp_path / "nd.json"
    raw = _raw(version=2)
    cfg = load_config_from_bytes(raw, p)
    assert p.exists()
    assert p.read_bytes() == raw
    assert cfg.version == 2
    print("  ✅ test_load_from_bytes_persists")


# ── mgmt endpoint tests ───────────────────────────────────────────────────────

def test_health_ready(tmp_path):
    srv  = _fake_server(_raw(version=1))
    mgmt = MgmtServer("127.0.0.1", 19200)
    mgmt.start(srv)
    _wait("http://127.0.0.1:19200/health")

    h = json.loads(urllib.request.urlopen("http://127.0.0.1:19200/health").read())
    assert h["status"] == "ok"
    assert h["version"] == 1

    r = json.loads(urllib.request.urlopen("http://127.0.0.1:19200/ready").read())
    assert r["status"] == "ready"

    mgmt.stop()
    print("  ✅ test_health_ready")


def test_config_raw_endpoint(tmp_path):
    raw  = _raw(version=3)
    srv  = _fake_server(raw)
    mgmt = MgmtServer("127.0.0.1", 19201)
    mgmt.start(srv)
    _wait("http://127.0.0.1:19201/health")

    fetched = _fetch_raw_config("127.0.0.1:19201")
    assert fetched is not None
    assert json.loads(fetched)["server"]["config_version"] == 3

    mgmt.stop()
    print("  ✅ test_config_raw_endpoint")


def test_sync_applies_newer(tmp_path):
    """POST /sync with v2 on a v1 node → applied."""
    p   = tmp_path / "nd.json"
    srv = _fake_server(_raw(version=1), p)
    mgmt = MgmtServer("127.0.0.1", 19202)
    mgmt.start(srv)
    _wait("http://127.0.0.1:19202/health")

    new_raw = _raw(version=2, records=[{"name":"pushed.test","type":"A","value":"9.9.9.9"}])
    result  = _push_sync("127.0.0.1:19202", new_raw)
    assert result["status"] == "applied", result
    assert result["version"] == 2
    assert srv.config.version == 2
    assert srv.config.records[0].name == "pushed.test"
    # File must be persisted.
    assert json.loads(p.read_bytes())["server"]["config_version"] == 2

    mgmt.stop()
    print("  ✅ test_sync_applies_newer")


def test_sync_idempotent(tmp_path):
    """Pushing the same bytes twice → second call is already_current."""
    srv  = _fake_server(_raw(version=2))
    mgmt = MgmtServer("127.0.0.1", 19203)
    mgmt.start(srv)
    _wait("http://127.0.0.1:19203/health")

    new_raw = _raw(version=3)
    r1 = _push_sync("127.0.0.1:19203", new_raw)
    assert r1["status"] == "applied"

    r2 = _push_sync("127.0.0.1:19203", new_raw)
    assert r2["status"] == "already_current"

    mgmt.stop()
    print("  ✅ test_sync_idempotent")


def test_sync_rejects_stale(tmp_path):
    """POST /sync with v1 on a v5 node → rejected_stale (anti-rollback)."""
    srv  = _fake_server(_raw(version=5))
    mgmt = MgmtServer("127.0.0.1", 19204)
    mgmt.start(srv)
    _wait("http://127.0.0.1:19204/health")

    stale = _raw(version=1)
    try:
        _push_sync("127.0.0.1:19204", stale)
        result = _push_sync("127.0.0.1:19204", stale)
    except urllib.error.HTTPError as exc:
        result = json.loads(exc.read())
    # Should be rejected or at least return "rejected_stale"
    assert result.get("status") == "rejected_stale" or result.get("http_error") == 409, result
    assert srv.config.version == 5, "version must not have rolled back"

    mgmt.stop()
    print("  ✅ test_sync_rejects_stale")


def test_catchup_pull(tmp_path):
    """Node A (v1) catches up from Node B (v5) via catchup_from_peers."""
    # Node B — has v5
    p_b  = tmp_path / "b.json"
    srv_b = _fake_server(_raw(version=5), p_b)
    mgmt_b = MgmtServer("127.0.0.1", 19205)
    mgmt_b.start(srv_b)
    _wait("http://127.0.0.1:19205/health")

    # Node A — has v1, peer = B
    p_a   = tmp_path / "a.json"
    raw_a = _raw(version=1, peers=["127.0.0.1:19205"])
    srv_a = _fake_server(raw_a, p_a)
    mgmt_a = MgmtServer("127.0.0.1", 19206)
    mgmt_a.start(srv_a)
    _wait("http://127.0.0.1:19206/health")

    result = mgmt_a.catchup_from_peers()
    assert result is not None, "should have caught up"
    assert result["version"] == 5
    assert srv_a.config.version == 5
    assert json.loads(p_a.read_bytes())["server"]["config_version"] == 5

    mgmt_a.stop()
    mgmt_b.stop()
    print("  ✅ test_catchup_pull")


def test_catchup_already_latest(tmp_path):
    """Node at v10 with a peer at v5 → no catchup needed."""
    srv_b  = _fake_server(_raw(version=5))
    mgmt_b = MgmtServer("127.0.0.1", 19207)
    mgmt_b.start(srv_b)
    _wait("http://127.0.0.1:19207/health")

    raw_a  = _raw(version=10, peers=["127.0.0.1:19207"])
    srv_a  = _fake_server(raw_a)
    mgmt_a = MgmtServer("127.0.0.1", 19208)
    mgmt_a.start(srv_a)
    _wait("http://127.0.0.1:19208/health")

    result = mgmt_a.catchup_from_peers()
    assert result is None, "no catchup expected when already ahead"
    assert srv_a.config.version == 10

    mgmt_a.stop()
    mgmt_b.stop()
    print("  ✅ test_catchup_already_latest")


def test_cluster_status(tmp_path):
    """GET /cluster shows peer health and version."""
    srv_b  = _fake_server(_raw(version=4))
    mgmt_b = MgmtServer("127.0.0.1", 19209)
    mgmt_b.start(srv_b)
    _wait("http://127.0.0.1:19209/health")

    raw_a  = _raw(version=4, peers=["127.0.0.1:19209"])
    srv_a  = _fake_server(raw_a)
    mgmt_a = MgmtServer("127.0.0.1", 19210)
    mgmt_a.start(srv_a)
    _wait("http://127.0.0.1:19210/health")

    cluster = json.loads(
        urllib.request.urlopen("http://127.0.0.1:19210/cluster").read()
    )
    assert cluster["self"]["status"] == "ok"
    assert cluster["self"]["version"] == 4
    peer_info = cluster["peers"].get("127.0.0.1:19209", {})
    assert peer_info.get("reachable") is True
    assert peer_info.get("version") == 4

    mgmt_a.stop()
    mgmt_b.stop()
    print("  ✅ test_cluster_status")


def test_push_to_peers_full_flow(tmp_path):
    """Full push flow: reload on A bumps version and propagates to B and C."""
    p_b  = tmp_path / "b.json"
    p_c  = tmp_path / "c.json"

    # B and C start at v1
    srv_b  = _fake_server(_raw(version=1), p_b)
    mgmt_b = MgmtServer("127.0.0.1", 19211)
    mgmt_b.start(srv_b)
    _wait("http://127.0.0.1:19211/health")

    srv_c  = _fake_server(_raw(version=1), p_c)
    mgmt_c = MgmtServer("127.0.0.1", 19212)
    mgmt_c.start(srv_c)
    _wait("http://127.0.0.1:19212/health")

    # A has v2 and peers pointing at B and C
    raw_a2 = _raw(version=2,
                  records=[{"name":"new.test","type":"A","value":"1.2.3.4"}],
                  peers=["127.0.0.1:19211", "127.0.0.1:19212"])
    srv_a  = _fake_server(raw_a2)
    mgmt_a = MgmtServer("127.0.0.1", 19213)
    mgmt_a.start(srv_a)
    _wait("http://127.0.0.1:19213/health")

    results = mgmt_a.push_to_peers(srv_a.config)
    assert results["127.0.0.1:19211"]["status"] == "applied"
    assert results["127.0.0.1:19212"]["status"] == "applied"

    for srv in (srv_b, srv_c):
        assert srv.config.version == 2
        assert srv.config.records[0].name == "new.test"

    mgmt_a.stop()
    mgmt_b.stop()
    mgmt_c.stop()
    print("  ✅ test_push_to_peers_full_flow")


# ── run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Running NanoDNS HA tests...")

    # unit
    test_version_in_raw()        ; print("  ✅ test_version_in_raw")
    test_bump_version()          ; print("  ✅ test_bump_version")
    test_set_version()           ; print("  ✅ test_set_version")
    test_checksum_stable()       ; print("  ✅ test_checksum_stable")
    test_checksum_changes_with_content() ; print("  ✅ test_checksum_changes_with_content")

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        test_load_from_bytes_persists(tmp / "t1")
        test_health_ready(tmp / "t2")
        test_config_raw_endpoint(tmp / "t3")
        test_sync_applies_newer(tmp / "t4")
        test_sync_idempotent(tmp / "t5")
        test_sync_rejects_stale(tmp / "t6")
        test_catchup_pull(tmp / "t7")
        test_catchup_already_latest(tmp / "t8")
        test_cluster_status(tmp / "t9")
        test_push_to_peers_full_flow(tmp / "t10")

    print("\n✅ All HA tests passed")
