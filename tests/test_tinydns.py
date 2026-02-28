"""Tests for NanoDNS."""

import struct
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nanodns.protocol import (
    encode_name, decode_name, parse_message, build_message,
    DNSMessage, DNSQuestion, QType, QClass,
    encode_a, encode_aaaa, encode_cname, encode_txt, encode_mx,
)
from nanodns.config import load_config, _parse_config
from nanodns.cache import DNSCache
from nanodns.handler import DNSHandler


# ─── Protocol Tests ──────────────────────────────────────────────────────────

def test_encode_decode_name():
    name = "web.internal.lan"
    encoded = encode_name(name)
    decoded, _ = decode_name(encoded, 0)
    assert decoded == name


def test_encode_name_root():
    assert encode_name(".") == b"\x00"


def test_encode_a():
    assert encode_a("192.168.1.1") == b"\xc0\xa8\x01\x01"


def test_encode_aaaa():
    data = encode_aaaa("::1")
    assert len(data) == 16


def test_encode_txt():
    data = encode_txt("hello")
    assert data == b"\x05hello"


def test_encode_mx():
    data = encode_mx(10, "mail.example.com")
    assert data[:2] == b"\x00\x0a"  # priority=10


def test_parse_build_roundtrip():
    """Build a query and parse it back."""
    msg = DNSMessage(msg_id=1234, flags=0x0100)
    msg.questions.append(DNSQuestion(name="example.com", qtype=QType.A, qclass=QClass.IN))
    raw = build_message(msg)
    parsed = parse_message(raw)
    assert parsed.msg_id == 1234
    assert len(parsed.questions) == 1
    assert parsed.questions[0].name == "example.com"
    assert parsed.questions[0].qtype == QType.A


# ─── Config Tests ─────────────────────────────────────────────────────────────

SAMPLE_CONFIG = {
    "server": {"host": "127.0.0.1", "port": 5353, "upstream": ["8.8.8.8"]},
    "zones": {
        "test.lan": {
            "soa": {"mname": "ns1.test.lan", "rname": "admin.test.lan"}
        }
    },
    "records": [
        {"name": "web.test.lan", "type": "A", "value": "10.0.0.1", "ttl": 60},
        {"name": "api.test.lan", "type": "CNAME", "value": "web.test.lan"},
        {"name": "app.test.lan", "type": "A", "value": "10.0.0.2", "wildcard": True},
    ],
    "rewrites": [
        {"match": "blocked.com", "action": "nxdomain"},
        {"match": "*.ads.com", "action": "nxdomain"},
    ],
}


def make_config():
    return _parse_config(SAMPLE_CONFIG, None)


def test_config_parses_server():
    cfg = make_config()
    assert cfg.server.host == "127.0.0.1"
    assert cfg.server.port == 5353
    assert cfg.server.upstream == ["8.8.8.8"]


def test_config_parses_records():
    cfg = make_config()
    assert len(cfg.records) == 3


def test_config_get_records_exact():
    cfg = make_config()
    recs = cfg.get_records("web.test.lan", "A")
    assert len(recs) == 1
    assert recs[0].value == "10.0.0.1"


def test_config_get_records_wildcard():
    cfg = make_config()
    recs = cfg.get_records("foo.app.test.lan", "A")
    assert len(recs) == 1
    assert recs[0].value == "10.0.0.2"


def test_config_get_records_no_match():
    cfg = make_config()
    recs = cfg.get_records("notexist.test.lan", "A")
    assert recs == []


def test_config_rewrite_exact():
    cfg = make_config()
    rw = cfg.get_rewrite("blocked.com")
    assert rw is not None
    assert rw.action == "nxdomain"


def test_config_rewrite_wildcard():
    cfg = make_config()
    rw = cfg.get_rewrite("track.ads.com")
    assert rw is not None


def test_config_rewrite_no_match():
    cfg = make_config()
    rw = cfg.get_rewrite("google.com")
    assert rw is None


# ─── Cache Tests ──────────────────────────────────────────────────────────────

def make_dummy_msg(msg_id=1):
    return DNSMessage(msg_id=msg_id, flags=0x8180)


def test_cache_set_get():
    cache = DNSCache(max_size=10)
    msg = make_dummy_msg()
    cache.set("example.com", QType.A, QClass.IN, msg, ttl=60)
    result = cache.get("example.com", QType.A, QClass.IN)
    assert result is not None
    assert result.msg_id == 1


def test_cache_miss():
    cache = DNSCache()
    result = cache.get("notcached.com", QType.A, QClass.IN)
    assert result is None


def test_cache_stats():
    cache = DNSCache()
    cache.set("a.com", QType.A, QClass.IN, make_dummy_msg(), ttl=60)
    cache.get("a.com", QType.A, QClass.IN)  # hit
    cache.get("b.com", QType.A, QClass.IN)  # miss
    stats = cache.stats
    assert stats["hits"] == 1
    assert stats["misses"] == 1
    assert stats["hit_rate"] == 50.0


def test_cache_eviction():
    cache = DNSCache(max_size=3)
    for i in range(5):
        cache.set(f"host{i}.com", QType.A, QClass.IN, make_dummy_msg(i), ttl=60)
    assert cache.stats["size"] <= 3


def test_cache_invalidate():
    cache = DNSCache()
    cache.set("web.test.lan", QType.A, QClass.IN, make_dummy_msg(), ttl=60)
    cache.invalidate("web.test.lan")
    assert cache.get("web.test.lan", QType.A, QClass.IN) is None


# ─── Handler Tests ────────────────────────────────────────────────────────────

def build_query(name: str, qtype: int = QType.A) -> bytes:
    msg = DNSMessage(msg_id=42, flags=0x0100)
    msg.questions.append(DNSQuestion(name=name, qtype=qtype, qclass=QClass.IN))
    return build_message(msg)


def test_handler_resolves_local_a():
    cfg = make_config()
    cache = DNSCache()
    handler = DNSHandler(cfg, cache)

    raw = build_query("web.test.lan", QType.A)
    resp_raw = handler.handle(raw)
    resp = parse_message(resp_raw)
    assert resp.is_response
    assert len(resp.answers) == 1
    assert resp.answers[0].rdata == encode_a("10.0.0.1")


def test_handler_nxdomain_in_zone():
    cfg = make_config()
    cache = DNSCache()
    handler = DNSHandler(cfg, cache)

    raw = build_query("missing.test.lan", QType.A)
    resp_raw = handler.handle(raw)
    resp = parse_message(resp_raw)
    assert resp.is_response
    assert resp.rcode == 3  # NXDOMAIN


def test_handler_rewrite_nxdomain():
    cfg = make_config()
    cache = DNSCache()
    handler = DNSHandler(cfg, cache)

    raw = build_query("blocked.com", QType.A)
    resp_raw = handler.handle(raw)
    resp = parse_message(resp_raw)
    assert resp.rcode == 3  # NXDOMAIN


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
