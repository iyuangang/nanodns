"""
Unit tests for nanodns.config
Covers: _parse_config, load_config, generate_example_config,
        get_records (exact / wildcard / case), get_rewrite, is_stale.
"""

import json
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nanodns.config import _parse_config, load_config, generate_example_config


# ═══════════════════════════════════════════════════════════════════════════════
# Shared fixture
# ═══════════════════════════════════════════════════════════════════════════════

BASE_CONFIG = {
    "server": {
        "host": "127.0.0.1", "port": 5353,
        "upstream": ["8.8.8.8"],
        "upstream_timeout": 2, "upstream_port": 53,
        "cache_enabled": True, "cache_ttl": 300, "cache_size": 100,
        "log_level": "WARNING", "log_queries": False, "hot_reload": False,
    },
    "zones": {
        "test.lan": {
            "soa": {
                "mname": "ns1.test.lan", "rname": "admin.test.lan",
                "serial": 20240101, "refresh": 3600, "retry": 900,
                "expire": 604800, "minimum": 300,
            },
            "ns": ["ns1.test.lan"],
        }
    },
    "records": [
        {"name": "web.test.lan",  "type": "A",     "value": "10.0.0.10", "ttl": 60},
        {"name": "web.test.lan",  "type": "A",     "value": "10.0.0.11", "ttl": 60},
        {"name": "ipv6.test.lan", "type": "AAAA",  "value": "fd00::1",   "ttl": 60},
        {"name": "api.test.lan",  "type": "CNAME", "value": "web.test.lan"},
        {"name": "test.lan",      "type": "MX",    "value": "mail.test.lan",  "priority": 10},
        {"name": "test.lan",      "type": "MX",    "value": "mail2.test.lan", "priority": 20},
        {"name": "test.lan",      "type": "TXT",   "value": "v=spf1 ~all"},
        {"name": "test.lan",      "type": "NS",    "value": "ns1.test.lan"},
        {"name": "app.test.lan",  "type": "A",     "value": "10.0.1.1", "wildcard": True},
        {"name": "1.0.0.10.in-addr.arpa", "type": "PTR", "value": "web.test.lan"},
    ],
    "rewrites": [
        {"match": "blocked.com",   "action": "nxdomain"},
        {"match": "*.ads.example", "action": "nxdomain"},
    ],
}


@pytest.fixture
def cfg():
    return _parse_config(BASE_CONFIG, None)


# ═══════════════════════════════════════════════════════════════════════════════
# Parsing defaults
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfigDefaults:

    def test_empty_config_applies_defaults(self):
        cfg = _parse_config({}, None)
        assert cfg.server.host == "0.0.0.0"
        assert cfg.server.port == 53
        assert cfg.server.cache_enabled is True
        assert cfg.server.hot_reload is True

    def test_server_fields_parsed(self, cfg):
        assert cfg.server.host == "127.0.0.1"
        assert cfg.server.port == 5353
        assert cfg.server.upstream == ["8.8.8.8"]
        assert cfg.server.log_queries is False

    def test_zone_soa_parsed(self, cfg):
        zone = cfg.zones["test.lan"]
        assert zone.soa.mname == "ns1.test.lan"
        assert zone.soa.serial == 20240101
        assert "ns1.test.lan" in zone.ns

    def test_records_total(self, cfg):
        assert len(cfg.records) == 10


# ═══════════════════════════════════════════════════════════════════════════════
# Record lookup
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetRecords:

    def test_a_multi(self, cfg):
        recs = cfg.get_records("web.test.lan", "A")
        assert len(recs) == 2
        assert {r.value for r in recs} == {"10.0.0.10", "10.0.0.11"}

    def test_aaaa(self, cfg):
        assert cfg.get_records("ipv6.test.lan", "AAAA")[0].value == "fd00::1"

    def test_cname(self, cfg):
        assert cfg.get_records("api.test.lan", "CNAME")[0].value == "web.test.lan"

    def test_mx_multi(self, cfg):
        recs = cfg.get_records("test.lan", "MX")
        assert len(recs) == 2
        assert {r.priority for r in recs} == {10, 20}

    def test_txt(self, cfg):
        assert len(cfg.get_records("test.lan", "TXT")) == 1

    def test_ns(self, cfg):
        assert cfg.get_records("test.lan", "NS")[0].value == "ns1.test.lan"

    def test_ptr(self, cfg):
        assert cfg.get_records("1.0.0.10.in-addr.arpa", "PTR")[0].value == "web.test.lan"

    def test_no_match_returns_empty(self, cfg):
        assert cfg.get_records("ghost.test.lan", "A") == []

    def test_case_insensitive(self, cfg):
        assert len(cfg.get_records("WEB.TEST.LAN", "A")) == 2

    def test_trailing_dot_stripped(self, cfg):
        assert len(cfg.get_records("web.test.lan.", "A")) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# Wildcard records
# ═══════════════════════════════════════════════════════════════════════════════

class TestWildcardRecords:

    def test_single_level_matches(self, cfg):
        recs = cfg.get_records("foo.app.test.lan", "A")
        assert len(recs) == 1 and recs[0].value == "10.0.1.1"

    def test_two_levels_no_match(self, cfg):
        assert cfg.get_records("a.b.app.test.lan", "A") == []


# ═══════════════════════════════════════════════════════════════════════════════
# Rewrites
# ═══════════════════════════════════════════════════════════════════════════════

class TestRewrites:

    def test_exact_match(self, cfg):
        rw = cfg.get_rewrite("blocked.com")
        assert rw is not None and rw.action == "nxdomain"

    def test_wildcard_match(self, cfg):
        assert cfg.get_rewrite("tracker.ads.example") is not None

    def test_no_match(self, cfg):
        assert cfg.get_rewrite("google.com") is None

    def test_partial_hostname_no_match(self, cfg):
        assert cfg.get_rewrite("notblocked.com") is None

    def test_subdomain_of_exact_rule_no_match(self, cfg):
        # "blocked.com" rule must not match "sub.blocked.com"
        assert cfg.get_rewrite("sub.blocked.com") is None


# ═══════════════════════════════════════════════════════════════════════════════
# File loading
# ═══════════════════════════════════════════════════════════════════════════════

class TestLoadConfig:

    def test_load_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(BASE_CONFIG, f)
            path = f.name
        try:
            cfg = load_config(path)
            assert cfg.server.port == 5353
        finally:
            os.unlink(path)

    def test_no_path_uses_defaults(self):
        assert load_config(None).server.host == "0.0.0.0"

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_config("/does/not/exist.json")

    def test_generate_example_config(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            generate_example_config(path)
            data = json.loads(open(path).read())
            assert "server" in data and "records" in data
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════════════
# Hot-reload staleness detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestIsStale:

    def test_no_path_never_stale(self, cfg):
        assert cfg._path is None
        assert cfg.is_stale() is False

    def test_hot_reload_off_never_stale(self, cfg):
        cfg.server.hot_reload = False
        cfg._path = "/fake/path"
        assert cfg.is_stale() is False

    def test_oserror_returns_false(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text("{}")
        cfg = load_config(str(p))
        cfg.server.hot_reload = True
        p.unlink()
        assert cfg.is_stale() is False

    def test_mtime_changed_is_stale(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps(BASE_CONFIG))
        cfg = load_config(str(p))
        cfg.server.hot_reload = True
        cfg._mtime = 0.0          # force mismatch
        assert cfg.is_stale() is True
