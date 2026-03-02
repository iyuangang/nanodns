"""
Unit tests for NanoDNS.
Covers: protocol, config, cache, handler — including edge cases.
"""

import copy
import json
import socket
import tempfile
import time
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nanodns.protocol import (
    DNSMessage, DNSQuestion, DNSRecord,
    QType, QClass,
    encode_name, decode_name,
    encode_a, encode_aaaa, encode_cname, encode_txt,
    encode_mx, encode_ns, encode_ptr, encode_soa,
    parse_message, build_message,
)
from nanodns.config import _parse_config, load_config, generate_example_config
from nanodns.cache import DNSCache
from nanodns.handler import DNSHandler, RCODE_NXDOMAIN, RCODE_SERVFAIL, RCODE_FORMERR


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

SAMPLE_CONFIG = {
    "server": {
        "host": "127.0.0.1",
        "port": 5353,
        "upstream": ["8.8.8.8"],
        "upstream_timeout": 2,
        "cache_enabled": True,
        "cache_ttl": 300,
        "cache_size": 100,
        "log_level": "WARNING",
        "log_queries": False,
        "hot_reload": False,
    },
    "zones": {
        "test.lan": {
            "soa": {
                "mname": "ns1.test.lan",
                "rname": "admin.test.lan",
                "serial": 2024010101,
                "refresh": 3600,
                "retry": 900,
                "expire": 604800,
                "minimum": 300,
            },
            "ns": ["ns1.test.lan"],
        }
    },
    "records": [
        {"name": "ns1.test.lan",    "type": "A",     "value": "10.0.0.1",   "ttl": 3600},
        {"name": "web.test.lan",    "type": "A",     "value": "10.0.0.10",  "ttl": 60},
        {"name": "web.test.lan",    "type": "A",     "value": "10.0.0.11",  "ttl": 60},   # multi-A
        {"name": "ipv6.test.lan",   "type": "AAAA",  "value": "fd00::1",    "ttl": 60},
        {"name": "api.test.lan",    "type": "CNAME", "value": "web.test.lan"},
        {"name": "test.lan",        "type": "MX",    "value": "mail.test.lan", "priority": 10},
        {"name": "test.lan",        "type": "MX",    "value": "mail2.test.lan", "priority": 20},
        {"name": "test.lan",        "type": "TXT",   "value": "v=spf1 ~all"},
        {"name": "test.lan",        "type": "NS",    "value": "ns1.test.lan"},
        {"name": "app.test.lan",    "type": "A",     "value": "10.0.1.1",   "wildcard": True},
        {"name": "1.0.0.10.in-addr.arpa", "type": "PTR", "value": "web.test.lan"},
    ],
    "rewrites": [
        {"match": "blocked.com",      "action": "nxdomain"},
        {"match": "*.ads.example",    "action": "nxdomain"},
    ],
}


@pytest.fixture
def cfg():
    return _parse_config(SAMPLE_CONFIG, None)


@pytest.fixture
def handler(cfg):
    return DNSHandler(cfg, DNSCache())


def make_query(name: str, qtype: int = QType.A, msg_id: int = 42) -> bytes:
    msg = DNSMessage(msg_id=msg_id, flags=0x0100)
    msg.questions.append(DNSQuestion(name=name, qtype=qtype, qclass=QClass.IN))
    return build_message(msg)


def parse_response(raw: bytes) -> DNSMessage:
    return parse_message(raw)


# ═══════════════════════════════════════════════════════════════════════════════
# Protocol — encoding
# ═══════════════════════════════════════════════════════════════════════════════

class TestProtocolEncoding:

    def test_encode_name_single_label(self):
        enc = encode_name("com")
        assert enc == b"\x03com\x00"

    def test_encode_name_multi_label(self):
        enc = encode_name("web.internal.lan")
        dec, _ = decode_name(enc, 0)
        assert dec == "web.internal.lan"

    def test_encode_name_root(self):
        assert encode_name(".") == b"\x00"

    def test_encode_name_trailing_dot(self):
        enc1 = encode_name("example.com")
        enc2 = encode_name("example.com.")
        assert enc1 == enc2

    def test_decode_name_with_offset(self):
        # Prepend 4 bytes of garbage, decode from offset 4
        data = b"\x00" * 4 + encode_name("foo.bar")
        name, end = decode_name(data, 4)
        assert name == "foo.bar"

    def test_encode_a_loopback(self):
        assert encode_a("127.0.0.1") == b"\x7f\x00\x00\x01"

    def test_encode_a_broadcast(self):
        assert encode_a("255.255.255.255") == b"\xff\xff\xff\xff"

    def test_encode_aaaa_loopback(self):
        data = encode_aaaa("::1")
        assert len(data) == 16
        assert data[-1] == 1

    def test_encode_aaaa_full(self):
        data = encode_aaaa("2001:db8::1")
        assert len(data) == 16

    def test_encode_txt_empty(self):
        data = encode_txt("")
        assert data == b"\x00"

    def test_encode_txt_long(self):
        text = "a" * 100
        data = encode_txt(text)
        assert data[0] == 100
        assert data[1:] == text.encode()

    def test_encode_mx_priority(self):
        data = encode_mx(20, "mail.example.com")
        assert data[:2] == b"\x00\x14"  # 20 in big-endian

    def test_encode_soa(self):
        data = encode_soa("ns1.test.lan", "admin.test.lan",
                          2024010101, 3600, 900, 604800, 300)
        assert len(data) > 0

    def test_encode_ptr(self):
        data = encode_ptr("web.test.lan")
        name, _ = decode_name(data, 0)
        assert name == "web.test.lan"

    def test_encode_ns(self):
        data = encode_ns("ns1.test.lan")
        name, _ = decode_name(data, 0)
        assert name == "ns1.test.lan"


# ═══════════════════════════════════════════════════════════════════════════════
# Protocol — message parsing
# ═══════════════════════════════════════════════════════════════════════════════

class TestProtocolMessages:

    def test_query_roundtrip(self):
        msg = DNSMessage(msg_id=1234, flags=0x0100)
        msg.questions.append(DNSQuestion("example.com", QType.A, QClass.IN))
        raw = build_message(msg)
        parsed = parse_message(raw)
        assert parsed.msg_id == 1234
        assert parsed.questions[0].name == "example.com"
        assert parsed.questions[0].qtype == QType.A

    def test_response_flags(self):
        msg = DNSMessage(msg_id=1, flags=0x8180)  # QR=1, AA=1, RD=1, RA=1
        assert msg.is_response
        assert not msg.is_query

    def test_query_flags(self):
        msg = DNSMessage(msg_id=1, flags=0x0100)
        assert msg.is_query
        assert not msg.is_response

    def test_rcode_extraction(self):
        msg = DNSMessage(msg_id=1, flags=0x8183)  # rcode=3 (NXDOMAIN)
        assert msg.rcode == 3

    def test_set_rcode(self):
        msg = DNSMessage(msg_id=1, flags=0x8180)
        msg.set_rcode(3)
        assert msg.rcode == 3
        msg.set_rcode(0)
        assert msg.rcode == 0

    def test_parse_too_short_raises(self):
        with pytest.raises((ValueError, Exception)):
            parse_message(b"\x00\x01")

    def test_multiple_questions(self):
        msg = DNSMessage(msg_id=1, flags=0x0100)
        msg.questions.append(DNSQuestion("a.com", QType.A, QClass.IN))
        msg.questions.append(DNSQuestion("b.com", QType.AAAA, QClass.IN))
        raw = build_message(msg)
        parsed = parse_message(raw)
        assert len(parsed.questions) == 2
        assert parsed.questions[1].name == "b.com"

    def test_response_with_answer(self):
        msg = DNSMessage(msg_id=5, flags=0x8180)
        msg.questions.append(DNSQuestion("web.test.lan", QType.A, QClass.IN))
        msg.answers.append(DNSRecord(
            name="web.test.lan", rtype=QType.A, rclass=QClass.IN,
            ttl=300, rdata=encode_a("10.0.0.1")
        ))
        raw = build_message(msg)
        parsed = parse_message(raw)
        assert len(parsed.answers) == 1
        assert parsed.answers[0].rdata == encode_a("10.0.0.1")
        assert parsed.answers[0].ttl == 300

    def test_qtype_name(self):
        q = DNSQuestion("test.com", QType.AAAA, QClass.IN)
        assert q.qtype_name == "AAAA"


# ═══════════════════════════════════════════════════════════════════════════════
# Config
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfig:

    def test_server_defaults(self):
        cfg = _parse_config({}, None)
        assert cfg.server.host == "0.0.0.0"
        assert cfg.server.port == 53
        assert cfg.server.cache_enabled is True

    def test_server_override(self, cfg):
        assert cfg.server.host == "127.0.0.1"
        assert cfg.server.port == 5353
        assert cfg.server.log_queries is False

    def test_zones_parsed(self, cfg):
        assert "test.lan" in cfg.zones
        zone = cfg.zones["test.lan"]
        assert zone.soa is not None
        assert zone.soa.mname == "ns1.test.lan"
        assert zone.soa.serial == 2024010101
        assert "ns1.test.lan" in zone.ns

    def test_records_count(self, cfg):
        assert len(cfg.records) == 11

    def test_get_records_exact_a(self, cfg):
        recs = cfg.get_records("web.test.lan", "A")
        assert len(recs) == 2
        values = {r.value for r in recs}
        assert "10.0.0.10" in values
        assert "10.0.0.11" in values

    def test_get_records_aaaa(self, cfg):
        recs = cfg.get_records("ipv6.test.lan", "AAAA")
        assert len(recs) == 1
        assert recs[0].value == "fd00::1"

    def test_get_records_cname(self, cfg):
        recs = cfg.get_records("api.test.lan", "CNAME")
        assert len(recs) == 1
        assert recs[0].value == "web.test.lan"

    def test_get_records_mx_multiple(self, cfg):
        recs = cfg.get_records("test.lan", "MX")
        assert len(recs) == 2
        priorities = {r.priority for r in recs}
        assert 10 in priorities
        assert 20 in priorities

    def test_get_records_txt(self, cfg):
        recs = cfg.get_records("test.lan", "TXT")
        assert len(recs) == 1

    def test_get_records_ptr(self, cfg):
        recs = cfg.get_records("1.0.0.10.in-addr.arpa", "PTR")
        assert len(recs) == 1
        assert recs[0].value == "web.test.lan"

    def test_get_records_wildcard_match(self, cfg):
        recs = cfg.get_records("foo.app.test.lan", "A")
        assert len(recs) == 1
        assert recs[0].value == "10.0.1.1"

    def test_get_records_wildcard_no_double_subdomain(self, cfg):
        # Wildcard only matches one level deep
        recs = cfg.get_records("a.b.app.test.lan", "A")
        assert len(recs) == 0

    def test_get_records_case_insensitive(self, cfg):
        recs = cfg.get_records("WEB.TEST.LAN", "A")
        assert len(recs) == 2

    def test_get_records_no_match(self, cfg):
        assert cfg.get_records("notexist.test.lan", "A") == []

    def test_rewrite_exact_match(self, cfg):
        rw = cfg.get_rewrite("blocked.com")
        assert rw is not None
        assert rw.action == "nxdomain"

    def test_rewrite_wildcard_match(self, cfg):
        rw = cfg.get_rewrite("track.ads.example")
        assert rw is not None

    def test_rewrite_no_match(self, cfg):
        assert cfg.get_rewrite("google.com") is None

    def test_rewrite_partial_no_match(self, cfg):
        # "blocked.com.evil.com" should NOT match "blocked.com"
        assert cfg.get_rewrite("blocked.com.evil.com") is None

    def test_load_config_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(SAMPLE_CONFIG, f)
            path = f.name
        try:
            cfg = load_config(path)
            assert cfg.server.port == 5353
            assert len(cfg.records) == 11
        finally:
            os.unlink(path)

    def test_load_config_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path/config.json")

    def test_generate_example_config(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            generate_example_config(path)
            with open(path) as f:
                data = json.load(f)
            assert "server" in data
            assert "records" in data
            assert len(data["records"]) > 0
        finally:
            os.unlink(path)

    def test_config_not_stale_without_hot_reload(self, cfg):
        cfg.server.hot_reload = False
        assert cfg.is_stale() is False

    def test_config_not_stale_without_path(self, cfg):
        assert cfg._path is None
        assert cfg.is_stale() is False


# ═══════════════════════════════════════════════════════════════════════════════
# Cache
# ═══════════════════════════════════════════════════════════════════════════════

class TestCache:

    def make_msg(self, msg_id=1):
        return DNSMessage(msg_id=msg_id, flags=0x8180)

    def test_set_and_get(self):
        cache = DNSCache(max_size=10)
        cache.set("example.com", QType.A, QClass.IN, self.make_msg(1), ttl=60)
        result = cache.get("example.com", QType.A, QClass.IN)
        assert result is not None
        assert result.msg_id == 1

    def test_miss_returns_none(self):
        cache = DNSCache()
        assert cache.get("missing.com", QType.A, QClass.IN) is None

    def test_key_is_type_specific(self):
        cache = DNSCache()
        cache.set("example.com", QType.A, QClass.IN, self.make_msg(1), ttl=60)
        assert cache.get("example.com", QType.AAAA, QClass.IN) is None

    def test_key_is_case_insensitive(self):
        cache = DNSCache()
        cache.set("Example.COM", QType.A, QClass.IN, self.make_msg(1), ttl=60)
        result = cache.get("example.com", QType.A, QClass.IN)
        assert result is not None

    def test_ttl_zero_not_cached(self):
        cache = DNSCache()
        cache.set("example.com", QType.A, QClass.IN, self.make_msg(), ttl=0)
        assert cache.get("example.com", QType.A, QClass.IN) is None

    def test_expired_entry_returns_none(self):
        cache = DNSCache()
        cache.set("example.com", QType.A, QClass.IN, self.make_msg(), ttl=1)
        # Manually expire
        key = "example.com:1:1"
        cache._cache[key].expires_at = time.monotonic() - 1
        assert cache.get("example.com", QType.A, QClass.IN) is None

    def test_lru_eviction(self):
        cache = DNSCache(max_size=3)
        for i in range(5):
            cache.set(f"host{i}.com", QType.A, QClass.IN, self.make_msg(i), ttl=60)
        assert cache.stats["size"] == 3

    def test_lru_order_preserved(self):
        cache = DNSCache(max_size=3)
        cache.set("a.com", QType.A, QClass.IN, self.make_msg(1), ttl=60)
        cache.set("b.com", QType.A, QClass.IN, self.make_msg(2), ttl=60)
        cache.set("c.com", QType.A, QClass.IN, self.make_msg(3), ttl=60)
        # Access a.com to make it recently used
        cache.get("a.com", QType.A, QClass.IN)
        # Add d.com — should evict b.com (oldest unused)
        cache.set("d.com", QType.A, QClass.IN, self.make_msg(4), ttl=60)
        assert cache.get("a.com", QType.A, QClass.IN) is not None
        assert cache.get("b.com", QType.A, QClass.IN) is None

    def test_invalidate(self):
        cache = DNSCache()
        cache.set("web.test.lan", QType.A, QClass.IN, self.make_msg(), ttl=60)
        cache.set("web.test.lan", QType.AAAA, QClass.IN, self.make_msg(), ttl=60)
        cache.invalidate("web.test.lan")
        assert cache.get("web.test.lan", QType.A, QClass.IN) is None
        assert cache.get("web.test.lan", QType.AAAA, QClass.IN) is None

    def test_clear(self):
        cache = DNSCache()
        for i in range(5):
            cache.set(f"host{i}.com", QType.A, QClass.IN, self.make_msg(), ttl=60)
        cache.clear()
        assert cache.stats["size"] == 0

    def test_prune_removes_expired(self):
        cache = DNSCache()
        cache.set("old.com", QType.A, QClass.IN, self.make_msg(), ttl=60)
        cache.set("new.com", QType.A, QClass.IN, self.make_msg(), ttl=60)
        # Expire old.com manually
        cache._cache["old.com:1:1"].expires_at = time.monotonic() - 1
        cache.prune()
        assert cache.stats["size"] == 1
        assert cache.get("new.com", QType.A, QClass.IN) is not None

    def test_stats_hit_rate(self):
        cache = DNSCache()
        cache.set("a.com", QType.A, QClass.IN, self.make_msg(), ttl=60)
        cache.get("a.com", QType.A, QClass.IN)   # hit
        cache.get("a.com", QType.A, QClass.IN)   # hit
        cache.get("b.com", QType.A, QClass.IN)   # miss
        stats = cache.stats
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert stats["hit_rate"] == pytest.approx(66.7, abs=0.1)

    def test_stats_zero_requests(self):
        cache = DNSCache()
        assert cache.stats["hit_rate"] == 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# Handler
# ═══════════════════════════════════════════════════════════════════════════════

class TestHandler:

    def test_resolve_a_record(self, handler):
        resp = parse_response(handler.handle(make_query("web.test.lan", QType.A)))
        assert resp.is_response
        assert resp.rcode == 0
        assert len(resp.answers) == 2
        rdatas = {a.rdata for a in resp.answers}
        assert encode_a("10.0.0.10") in rdatas
        assert encode_a("10.0.0.11") in rdatas

    def test_resolve_aaaa_record(self, handler):
        resp = parse_response(handler.handle(make_query("ipv6.test.lan", QType.AAAA)))
        assert resp.rcode == 0
        assert len(resp.answers) == 1
        assert resp.answers[0].rdata == encode_aaaa("fd00::1")

    def test_resolve_cname_record(self, handler):
        resp = parse_response(handler.handle(make_query("api.test.lan", QType.CNAME)))
        assert resp.rcode == 0
        assert len(resp.answers) == 1

    def test_resolve_mx_record(self, handler):
        resp = parse_response(handler.handle(make_query("test.lan", QType.MX)))
        assert resp.rcode == 0
        assert len(resp.answers) == 2

    def test_resolve_txt_record(self, handler):
        resp = parse_response(handler.handle(make_query("test.lan", QType.TXT)))
        assert resp.rcode == 0
        assert len(resp.answers) == 1

    def test_resolve_ns_record(self, handler):
        resp = parse_response(handler.handle(make_query("test.lan", QType.NS)))
        assert resp.rcode == 0
        assert len(resp.answers) == 1

    def test_resolve_ptr_record(self, handler):
        resp = parse_response(handler.handle(make_query("1.0.0.10.in-addr.arpa", QType.PTR)))
        assert resp.rcode == 0
        assert len(resp.answers) == 1

    def test_resolve_soa_record(self, handler):
        resp = parse_response(handler.handle(make_query("test.lan", QType.SOA)))
        assert resp.rcode == 0
        assert len(resp.answers) == 1

    def test_nxdomain_within_zone(self, handler):
        resp = parse_response(handler.handle(make_query("ghost.test.lan", QType.A)))
        assert resp.rcode == RCODE_NXDOMAIN

    def test_rewrite_exact_nxdomain(self, handler):
        resp = parse_response(handler.handle(make_query("blocked.com", QType.A)))
        assert resp.rcode == RCODE_NXDOMAIN

    def test_rewrite_wildcard_nxdomain(self, handler):
        resp = parse_response(handler.handle(make_query("tracker.ads.example", QType.A)))
        assert resp.rcode == RCODE_NXDOMAIN

    def test_malformed_packet_returns_empty_or_formerr(self, handler):
        result = handler.handle(b"\x00\x01\x02")
        # Either empty bytes or a FORMERR response
        assert isinstance(result, bytes)

    def test_empty_packet(self, handler):
        result = handler.handle(b"")
        assert isinstance(result, bytes)

    def test_msg_id_preserved(self, handler):
        raw = make_query("web.test.lan", QType.A, msg_id=9999)
        resp = parse_response(handler.handle(raw))
        assert resp.msg_id == 9999

    def test_response_is_response_flag(self, handler):
        raw = make_query("web.test.lan", QType.A)
        resp = parse_response(handler.handle(raw))
        assert resp.is_response

    def test_wildcard_resolves(self, handler):
        resp = parse_response(handler.handle(make_query("anything.app.test.lan", QType.A)))
        assert resp.rcode == 0
        assert len(resp.answers) == 1
        assert resp.answers[0].rdata == encode_a("10.0.1.1")

    def test_outside_zone_no_upstream_returns_servfail(self, cfg):
        # Disable upstream
        cfg.server.upstream = []
        handler = DNSHandler(cfg, DNSCache())
        resp = parse_response(handler.handle(make_query("external.com", QType.A)))
        assert resp.rcode == RCODE_SERVFAIL

    def test_cache_hit_on_second_call(self, cfg):
        cache = DNSCache()
        handler = DNSHandler(cfg, cache)
        # First call: served locally, cache stats shouldn't matter
        handler.handle(make_query("web.test.lan", QType.A))
        # Manually inject a cache entry for an external domain
        dummy = DNSMessage(msg_id=1, flags=0x8180)
        dummy.answers.append(DNSRecord("cached.com", QType.A, QClass.IN, 300, encode_a("1.2.3.4")))
        cache.set("cached.com", QType.A, QClass.IN, dummy, ttl=60)
        resp = parse_response(handler.handle(make_query("cached.com", QType.A)))
        assert resp.rcode == 0
        assert resp.answers[0].rdata == encode_a("1.2.3.4")
        stats = cache.stats
        assert stats["hits"] >= 1
