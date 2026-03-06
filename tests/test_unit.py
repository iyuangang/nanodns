"""
Unit tests for NanoDNS — targeting >90% coverage.
Covers: protocol, config, cache, handler (all branches), resolver (mocked).
"""

import copy
import json
import os
import socket
import sys
import tempfile
import time
from unittest.mock import MagicMock, patch, call

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
from nanodns.handler import (
    DNSHandler, encode_record, make_response,
    RCODE_NOERROR, RCODE_FORMERR, RCODE_SERVFAIL, RCODE_NXDOMAIN,
)
from nanodns.resolver import resolve_upstream, _query_udp


# ═══════════════════════════════════════════════════════════════════════════════
# Shared fixtures
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
        {"name": "test.lan",      "type": "MX",    "value": "mail.test.lan", "priority": 10},
        {"name": "test.lan",      "type": "MX",    "value": "mail2.test.lan","priority": 20},
        {"name": "test.lan",      "type": "TXT",   "value": "v=spf1 ~all"},
        {"name": "test.lan",      "type": "NS",    "value": "ns1.test.lan"},
        {"name": "app.test.lan",  "type": "A",     "value": "10.0.1.1",  "wildcard": True},
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


@pytest.fixture
def handler(cfg):
    return DNSHandler(cfg, DNSCache())


def make_query(name: str, qtype: int = QType.A, msg_id: int = 42) -> bytes:
    msg = DNSMessage(msg_id=msg_id, flags=0x0100)
    msg.questions.append(DNSQuestion(name=name, qtype=qtype, qclass=QClass.IN))
    return build_message(msg)


# ═══════════════════════════════════════════════════════════════════════════════
# Protocol — encoding
# ═══════════════════════════════════════════════════════════════════════════════

class TestProtocolEncoding:

    def test_encode_name_multi_label(self):
        enc = encode_name("web.internal.lan")
        dec, _ = decode_name(enc, 0)
        assert dec == "web.internal.lan"

    def test_encode_name_root(self):
        assert encode_name(".") == b"\x00"

    def test_encode_name_trailing_dot_stripped(self):
        assert encode_name("example.com") == encode_name("example.com.")

    def test_encode_name_single_label(self):
        enc = encode_name("localhost")
        dec, _ = decode_name(enc, 0)
        assert dec == "localhost"

    def test_decode_name_with_prefix_offset(self):
        data = b"\x00" * 4 + encode_name("foo.bar")
        name, _ = decode_name(data, 4)
        assert name == "foo.bar"

    def test_decode_name_compression_pointer(self):
        # Build a packet with a compression pointer manually
        # "example" at offset 0, then a pointer back to it
        suffix = encode_name("example.com")  # e.g. \x07example\x03com\x00
        # pointer = 0xC000 | 0 => b'\xc0\x00'
        data = suffix + b"\x03sub" + b"\xc0\x00"
        # decode from offset len(suffix): should read "sub" then follow pointer to "example.com"
        name, _ = decode_name(data, len(suffix))
        assert name == "sub.example.com"

    def test_encode_a_values(self):
        assert encode_a("192.168.1.1") == b"\xc0\xa8\x01\x01"
        assert encode_a("0.0.0.0") == b"\x00\x00\x00\x00"
        assert encode_a("255.255.255.255") == b"\xff\xff\xff\xff"

    def test_encode_aaaa_loopback(self):
        data = encode_aaaa("::1")
        assert len(data) == 16
        assert data[-1] == 1

    def test_encode_aaaa_full_address(self):
        data = encode_aaaa("2001:db8::1")
        assert len(data) == 16

    def test_encode_txt_normal(self):
        assert encode_txt("hello") == b"\x05hello"

    def test_encode_txt_empty(self):
        assert encode_txt("") == b"\x00"

    def test_encode_txt_long(self):
        text = "x" * 200
        data = encode_txt(text)
        assert data[0] == 200

    def test_encode_mx_priority_zero(self):
        data = encode_mx(0, "mail.example.com")
        assert data[:2] == b"\x00\x00"

    def test_encode_mx_priority_20(self):
        data = encode_mx(20, "mail.example.com")
        assert data[:2] == b"\x00\x14"

    def test_encode_soa_produces_bytes(self):
        data = encode_soa("ns1.t.lan", "admin.t.lan", 1, 3600, 900, 604800, 300)
        assert len(data) > 20

    def test_encode_ptr_roundtrip(self):
        data = encode_ptr("web.test.lan")
        name, _ = decode_name(data, 0)
        assert name == "web.test.lan"

    def test_encode_ns_roundtrip(self):
        data = encode_ns("ns1.test.lan")
        name, _ = decode_name(data, 0)
        assert name == "ns1.test.lan"

    def test_encode_cname_roundtrip(self):
        data = encode_cname("target.test.lan")
        name, _ = decode_name(data, 0)
        assert name == "target.test.lan"

    def test_rtype_name_known(self):
        r = DNSRecord("x", QType.A, QClass.IN, 300, b"")
        assert r.rtype_name == "A"

    def test_rtype_name_unknown(self):
        r = DNSRecord("x", 999, QClass.IN, 300, b"")
        assert r.rtype_name == "TYPE999"


# ═══════════════════════════════════════════════════════════════════════════════
# Protocol — message parsing & building
# ═══════════════════════════════════════════════════════════════════════════════

class TestProtocolMessages:

    def test_query_roundtrip_a(self):
        msg = DNSMessage(msg_id=1, flags=0x0100)
        msg.questions.append(DNSQuestion("example.com", QType.A, QClass.IN))
        parsed = parse_message(build_message(msg))
        assert parsed.msg_id == 1
        assert parsed.questions[0].name == "example.com"
        assert parsed.questions[0].qtype == QType.A

    def test_response_flag(self):
        msg = DNSMessage(msg_id=1, flags=0x8180)
        assert msg.is_response and not msg.is_query

    def test_query_flag(self):
        msg = DNSMessage(msg_id=1, flags=0x0100)
        assert msg.is_query and not msg.is_response

    def test_rcode_zero(self):
        assert DNSMessage(1, 0x8180).rcode == 0

    def test_rcode_nxdomain(self):
        assert DNSMessage(1, 0x8183).rcode == 3

    def test_set_rcode(self):
        msg = DNSMessage(1, 0x8180)
        msg.set_rcode(3)
        assert msg.rcode == 3
        msg.set_rcode(0)
        assert msg.rcode == 0

    def test_set_rcode_does_not_corrupt_other_flags(self):
        msg = DNSMessage(1, 0x8580)  # some extra flag bits
        msg.set_rcode(2)
        assert msg.rcode == 2
        assert msg.flags & 0xFFF0 == 0x8580  # other bits unchanged

    def test_parse_too_short_raises(self):
        with pytest.raises(Exception):
            parse_message(b"\x00\x01")

    def test_parse_empty_raises(self):
        with pytest.raises(Exception):
            parse_message(b"")

    def test_multiple_questions_roundtrip(self):
        msg = DNSMessage(msg_id=7, flags=0x0100)
        msg.questions.append(DNSQuestion("a.com", QType.A, QClass.IN))
        msg.questions.append(DNSQuestion("b.com", QType.AAAA, QClass.IN))
        parsed = parse_message(build_message(msg))
        assert len(parsed.questions) == 2
        assert parsed.questions[1].name == "b.com"

    def test_response_with_answer_roundtrip(self):
        msg = DNSMessage(msg_id=5, flags=0x8180)
        msg.questions.append(DNSQuestion("web.test.lan", QType.A, QClass.IN))
        msg.answers.append(DNSRecord("web.test.lan", QType.A, QClass.IN, 300, encode_a("10.0.0.1")))
        parsed = parse_message(build_message(msg))
        assert parsed.answers[0].rdata == encode_a("10.0.0.1")
        assert parsed.answers[0].ttl == 300

    def test_authority_and_additional_sections(self):
        msg = DNSMessage(msg_id=1, flags=0x8180)
        msg.authority.append(DNSRecord("test.lan", QType.NS, QClass.IN, 300, encode_ns("ns1.test.lan")))
        msg.additional.append(DNSRecord("ns1.test.lan", QType.A, QClass.IN, 300, encode_a("1.2.3.4")))
        parsed = parse_message(build_message(msg))
        assert len(parsed.authority) == 1
        assert len(parsed.additional) == 1

    def test_qtype_name(self):
        assert DNSQuestion("x", QType.AAAA, QClass.IN).qtype_name == "AAAA"
        assert DNSQuestion("x", QType.MX, QClass.IN).qtype_name == "MX"
        assert DNSQuestion("x", 9999, QClass.IN).qtype_name == "TYPE9999"


# ═══════════════════════════════════════════════════════════════════════════════
# Config
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfig:

    def test_defaults_when_empty(self):
        cfg = _parse_config({}, None)
        assert cfg.server.host == "0.0.0.0"
        assert cfg.server.port == 53
        assert cfg.server.cache_enabled is True
        assert cfg.server.hot_reload is True

    def test_server_fields(self, cfg):
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

    def test_get_records_exact_multi(self, cfg):
        recs = cfg.get_records("web.test.lan", "A")
        assert len(recs) == 2
        values = {r.value for r in recs}
        assert values == {"10.0.0.10", "10.0.0.11"}

    def test_get_records_aaaa(self, cfg):
        assert cfg.get_records("ipv6.test.lan", "AAAA")[0].value == "fd00::1"

    def test_get_records_cname(self, cfg):
        assert cfg.get_records("api.test.lan", "CNAME")[0].value == "web.test.lan"

    def test_get_records_mx_multi(self, cfg):
        recs = cfg.get_records("test.lan", "MX")
        assert len(recs) == 2
        assert {r.priority for r in recs} == {10, 20}

    def test_get_records_txt(self, cfg):
        assert len(cfg.get_records("test.lan", "TXT")) == 1

    def test_get_records_ns(self, cfg):
        assert cfg.get_records("test.lan", "NS")[0].value == "ns1.test.lan"

    def test_get_records_ptr(self, cfg):
        assert cfg.get_records("1.0.0.10.in-addr.arpa", "PTR")[0].value == "web.test.lan"

    def test_wildcard_one_level(self, cfg):
        recs = cfg.get_records("foo.app.test.lan", "A")
        assert len(recs) == 1 and recs[0].value == "10.0.1.1"

    def test_wildcard_two_levels_no_match(self, cfg):
        assert cfg.get_records("a.b.app.test.lan", "A") == []

    def test_wildcard_does_not_match_two_levels_deep_2(self, cfg):
        # wildcard on "app.test.lan" should not match "a.b.app.test.lan"
        assert cfg.get_records("a.b.app.test.lan", "A") == []

    def test_case_insensitive_lookup(self, cfg):
        assert len(cfg.get_records("WEB.TEST.LAN", "A")) == 2

    def test_trailing_dot_stripped(self, cfg):
        assert len(cfg.get_records("web.test.lan.", "A")) == 2

    def test_no_match_returns_empty(self, cfg):
        assert cfg.get_records("ghost.test.lan", "A") == []

    def test_rewrite_exact(self, cfg):
        rw = cfg.get_rewrite("blocked.com")
        assert rw is not None and rw.action == "nxdomain"

    def test_rewrite_wildcard(self, cfg):
        assert cfg.get_rewrite("tracker.ads.example") is not None

    def test_rewrite_no_match(self, cfg):
        assert cfg.get_rewrite("google.com") is None

    def test_rewrite_partial_hostname_no_match(self, cfg):
        assert cfg.get_rewrite("notblocked.com") is None

    def test_rewrite_subdomain_not_exact_blocked(self, cfg):
        # sub.blocked.com should NOT match exact rule for blocked.com
        assert cfg.get_rewrite("sub.blocked.com") is None

    def test_load_config_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(BASE_CONFIG, f)
            path = f.name
        try:
            cfg = load_config(path)
            assert cfg.server.port == 5353
        finally:
            os.unlink(path)

    def test_load_config_no_path_uses_defaults(self):
        cfg = load_config(None)
        assert cfg.server.host == "0.0.0.0"

    def test_load_config_missing_file_raises(self):
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

    def test_is_stale_no_path(self, cfg):
        assert cfg._path is None
        assert cfg.is_stale() is False

    def test_is_stale_hot_reload_off(self, cfg):
        cfg.server.hot_reload = False
        cfg._path = "/fake/path"
        assert cfg.is_stale() is False

    def test_is_stale_oserror(self, tmp_path):
        """OSError (e.g. file deleted) returns False gracefully."""
        p = tmp_path / "cfg.json"
        p.write_text("{}")
        cfg = load_config(str(p))
        cfg.server.hot_reload = True
        p.unlink()
        assert cfg.is_stale() is False

    def test_is_stale_modified(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps(BASE_CONFIG))
        cfg = load_config(str(p))
        cfg.server.hot_reload = True
        # Force mtime mismatch
        cfg._mtime = 0.0
        assert cfg.is_stale() is True


# ═══════════════════════════════════════════════════════════════════════════════
# Cache
# ═══════════════════════════════════════════════════════════════════════════════

class TestCache:

    def _msg(self, mid=1):
        return DNSMessage(msg_id=mid, flags=0x8180)

    def test_set_get(self):
        c = DNSCache()
        c.set("x.com", QType.A, QClass.IN, self._msg(1), ttl=60)
        assert c.get("x.com", QType.A, QClass.IN).msg_id == 1

    def test_miss(self):
        assert DNSCache().get("z.com", QType.A, QClass.IN) is None

    def test_different_qtypes_isolated(self):
        c = DNSCache()
        c.set("x.com", QType.A, QClass.IN, self._msg(1), ttl=60)
        assert c.get("x.com", QType.AAAA, QClass.IN) is None

    def test_case_insensitive_key(self):
        c = DNSCache()
        c.set("X.COM", QType.A, QClass.IN, self._msg(1), ttl=60)
        assert c.get("x.com", QType.A, QClass.IN) is not None

    def test_ttl_zero_skips_cache(self):
        c = DNSCache()
        c.set("x.com", QType.A, QClass.IN, self._msg(), ttl=0)
        assert c.get("x.com", QType.A, QClass.IN) is None

    def test_expired_entry_removed_on_get(self):
        c = DNSCache()
        c.set("x.com", QType.A, QClass.IN, self._msg(), ttl=60)
        key = list(c._cache.keys())[0]
        c._cache[key].expires_at = time.monotonic() - 1
        assert c.get("x.com", QType.A, QClass.IN) is None

    def test_lru_eviction_respects_max_size(self):
        c = DNSCache(max_size=3)
        for i in range(5):
            c.set(f"h{i}.com", QType.A, QClass.IN, self._msg(i), ttl=60)
        assert c.stats["size"] == 3

    def test_lru_access_order(self):
        c = DNSCache(max_size=3)
        c.set("a.com", QType.A, QClass.IN, self._msg(), ttl=60)
        c.set("b.com", QType.A, QClass.IN, self._msg(), ttl=60)
        c.set("c.com", QType.A, QClass.IN, self._msg(), ttl=60)
        c.get("a.com", QType.A, QClass.IN)     # touch a → b is now oldest
        c.set("d.com", QType.A, QClass.IN, self._msg(), ttl=60)  # evict b
        assert c.get("b.com", QType.A, QClass.IN) is None
        assert c.get("a.com", QType.A, QClass.IN) is not None

    def test_overwrite_existing_key(self):
        c = DNSCache()
        c.set("x.com", QType.A, QClass.IN, self._msg(1), ttl=60)
        c.set("x.com", QType.A, QClass.IN, self._msg(2), ttl=60)
        assert c.get("x.com", QType.A, QClass.IN).msg_id == 2

    def test_invalidate_removes_all_types_for_name(self):
        c = DNSCache()
        c.set("w.com", QType.A,    QClass.IN, self._msg(), ttl=60)
        c.set("w.com", QType.AAAA, QClass.IN, self._msg(), ttl=60)
        c.invalidate("w.com")
        assert c.get("w.com", QType.A, QClass.IN) is None
        assert c.get("w.com", QType.AAAA, QClass.IN) is None

    def test_clear_empties_cache(self):
        c = DNSCache()
        for i in range(5):
            c.set(f"h{i}.com", QType.A, QClass.IN, self._msg(), ttl=60)
        c.clear()
        assert c.stats["size"] == 0

    def test_prune_removes_expired_only(self):
        c = DNSCache()
        c.set("old.com", QType.A, QClass.IN, self._msg(), ttl=60)
        c.set("new.com", QType.A, QClass.IN, self._msg(), ttl=60)
        key = "old.com:1:1"
        c._cache[key].expires_at = time.monotonic() - 1
        c.prune()
        assert c.stats["size"] == 1
        assert c.get("new.com", QType.A, QClass.IN) is not None

    def test_stats_hit_rate_50(self):
        c = DNSCache()
        c.set("a.com", QType.A, QClass.IN, self._msg(), ttl=60)
        c.get("a.com", QType.A, QClass.IN)  # hit
        c.get("b.com", QType.A, QClass.IN)  # miss
        s = c.stats
        assert s["hits"] == 1 and s["misses"] == 1
        assert s["hit_rate"] == pytest.approx(50.0)

    def test_stats_zero_requests_hit_rate(self):
        assert DNSCache().stats["hit_rate"] == 0.0

    def test_stats_all_hits(self):
        c = DNSCache()
        c.set("a.com", QType.A, QClass.IN, self._msg(), ttl=60)
        c.get("a.com", QType.A, QClass.IN)
        c.get("a.com", QType.A, QClass.IN)
        assert c.stats["hit_rate"] == 100.0

    def test_remaining_ttl(self):
        c = DNSCache()
        c.set("a.com", QType.A, QClass.IN, self._msg(), ttl=60)
        key = list(c._cache.keys())[0]
        ttl = c._cache[key].remaining_ttl
        assert 58 <= ttl <= 60

    def test_thread_safety_basic(self):
        """Multiple threads writing and reading should not crash."""
        import threading
        c = DNSCache(max_size=50)
        errors = []

        def worker(i):
            try:
                c.set(f"h{i}.com", QType.A, QClass.IN, DNSMessage(i, 0x8180), ttl=60)
                c.get(f"h{i}.com", QType.A, QClass.IN)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert errors == []


# ═══════════════════════════════════════════════════════════════════════════════
# Handler — encode_record
# ═══════════════════════════════════════════════════════════════════════════════

class TestEncodeRecord:
    from nanodns.config import RecordEntry

    def _rec(self, rtype, value, priority=10):
        from nanodns.config import RecordEntry
        return RecordEntry(name="test", rtype=rtype, value=value,
                           ttl=300, priority=priority)

    def test_encode_a(self):
        assert encode_record(self._rec("A", "1.2.3.4")) == encode_a("1.2.3.4")

    def test_encode_aaaa(self):
        assert encode_record(self._rec("AAAA", "::1")) == encode_aaaa("::1")

    def test_encode_cname(self):
        assert encode_record(self._rec("CNAME", "target.lan")) == encode_cname("target.lan")

    def test_encode_ptr(self):
        assert encode_record(self._rec("PTR", "host.lan")) == encode_ptr("host.lan")

    def test_encode_ns(self):
        assert encode_record(self._rec("NS", "ns1.lan")) == encode_ns("ns1.lan")

    def test_encode_mx(self):
        assert encode_record(self._rec("MX", "mail.lan", 20)) == encode_mx(20, "mail.lan")

    def test_encode_txt(self):
        assert encode_record(self._rec("TXT", "hello")) == encode_txt("hello")

    def test_unsupported_type_returns_none(self):
        assert encode_record(self._rec("UNKNOWN", "value")) is None

    def test_bad_ip_returns_none(self):
        assert encode_record(self._rec("A", "not-an-ip")) is None

    def test_lowercase_type(self):
        assert encode_record(self._rec("a", "1.2.3.4")) == encode_a("1.2.3.4")


# ═══════════════════════════════════════════════════════════════════════════════
# Handler — request handling
# ═══════════════════════════════════════════════════════════════════════════════

class TestHandler:

    def test_a_record_multi(self, handler):
        resp = parse_message(handler.handle(make_query("web.test.lan")))
        assert resp.rcode == 0 and len(resp.answers) == 2

    def test_aaaa_record(self, handler):
        resp = parse_message(handler.handle(make_query("ipv6.test.lan", QType.AAAA)))
        assert resp.answers[0].rdata == encode_aaaa("fd00::1")

    def test_cname_record(self, handler):
        resp = parse_message(handler.handle(make_query("api.test.lan", QType.CNAME)))
        assert resp.rcode == 0

    def test_mx_record(self, handler):
        resp = parse_message(handler.handle(make_query("test.lan", QType.MX)))
        assert resp.rcode == 0 and len(resp.answers) == 2

    def test_txt_record(self, handler):
        assert parse_message(handler.handle(make_query("test.lan", QType.TXT))).rcode == 0

    def test_ns_record(self, handler):
        assert parse_message(handler.handle(make_query("test.lan", QType.NS))).rcode == 0

    def test_ptr_record(self, handler):
        resp = parse_message(handler.handle(make_query("1.0.0.10.in-addr.arpa", QType.PTR)))
        assert resp.rcode == 0

    def test_soa_record(self, handler):
        resp = parse_message(handler.handle(make_query("test.lan", QType.SOA)))
        assert resp.rcode == 0 and len(resp.answers) == 1

    def test_any_query_returns_all_types(self, handler):
        resp = parse_message(handler.handle(make_query("test.lan", QType.ANY)))
        assert resp.rcode == 0 and len(resp.answers) > 0

    def test_nxdomain_in_zone(self, handler):
        resp = parse_message(handler.handle(make_query("ghost.test.lan")))
        assert resp.rcode == RCODE_NXDOMAIN

    def test_nxdomain_zone_apex_no_record(self, handler):
        resp = parse_message(handler.handle(make_query("test.lan", QType.A)))
        assert resp.rcode == RCODE_NXDOMAIN

    def test_rewrite_exact_nxdomain(self, handler):
        assert parse_message(handler.handle(make_query("blocked.com"))).rcode == RCODE_NXDOMAIN

    def test_rewrite_wildcard_nxdomain(self, handler):
        assert parse_message(handler.handle(make_query("t.ads.example"))).rcode == RCODE_NXDOMAIN

    def test_wildcard_resolves(self, handler):
        resp = parse_message(handler.handle(make_query("foo.app.test.lan")))
        assert resp.answers[0].rdata == encode_a("10.0.1.1")

    def test_msg_id_echoed(self, handler):
        resp = parse_message(handler.handle(make_query("web.test.lan", msg_id=9999)))
        assert resp.msg_id == 9999

    def test_response_is_flagged(self, handler):
        resp = parse_message(handler.handle(make_query("web.test.lan")))
        assert resp.is_response

    def test_no_questions_returns_formerr(self, handler):
        msg = DNSMessage(msg_id=1, flags=0x0100)
        raw = build_message(msg)
        resp = parse_message(handler.handle(raw))
        assert resp.rcode == RCODE_FORMERR

    def test_malformed_bytes_returns_empty(self, handler):
        assert handler.handle(b"\x00\x01\x02") == b""

    def test_empty_bytes_returns_empty(self, handler):
        assert handler.handle(b"") == b""

    def test_no_upstream_returns_servfail(self, cfg):
        cfg.server.upstream = []
        h = DNSHandler(cfg, DNSCache())
        resp = parse_message(h.handle(make_query("external.com")))
        assert resp.rcode == RCODE_SERVFAIL

    def test_cache_is_used_for_external_domain(self, cfg):
        cache = DNSCache()
        dummy = DNSMessage(msg_id=1, flags=0x8180)
        dummy.answers.append(DNSRecord("cached.com", QType.A, QClass.IN, 300, encode_a("9.9.9.9")))
        cache.set("cached.com", QType.A, QClass.IN, dummy, ttl=60)
        h = DNSHandler(cfg, cache)
        resp = parse_message(h.handle(make_query("cached.com")))
        assert resp.answers[0].rdata == encode_a("9.9.9.9")
        assert cache.stats["hits"] == 1

    def test_upstream_response_is_cached(self, cfg):
        """Upstream response gets stored in cache."""
        cache = DNSCache()
        h = DNSHandler(cfg, cache)
        fake_resp = DNSMessage(msg_id=42, flags=0x8180)
        fake_resp.answers.append(DNSRecord("ext.com", QType.A, QClass.IN, 60, encode_a("1.1.1.1")))
        with patch("nanodns.handler.resolve_upstream", return_value=fake_resp):
            h.handle(make_query("ext.com"))
        assert cache.get("ext.com", QType.A, QClass.IN) is not None

    def test_upstream_none_returns_servfail(self, cfg):
        h = DNSHandler(cfg, DNSCache())
        with patch("nanodns.handler.resolve_upstream", return_value=None):
            resp = parse_message(h.handle(make_query("ext.com")))
        assert resp.rcode == RCODE_SERVFAIL

    def test_upstream_response_no_answers_not_cached(self, cfg):
        """Empty answer section should not be cached."""
        cache = DNSCache()
        h = DNSHandler(cfg, cache)
        fake_resp = DNSMessage(msg_id=42, flags=0x8180)  # no answers
        with patch("nanodns.handler.resolve_upstream", return_value=fake_resp):
            h.handle(make_query("ext.com"))
        assert cache.get("ext.com", QType.A, QClass.IN) is None

    def test_cache_disabled_upstream_not_cached(self, cfg):
        cfg.server.cache_enabled = False
        cache = DNSCache()
        h = DNSHandler(cfg, cache)
        fake_resp = DNSMessage(msg_id=42, flags=0x8180)
        fake_resp.answers.append(DNSRecord("ext.com", QType.A, QClass.IN, 60, encode_a("1.1.1.1")))
        with patch("nanodns.handler.resolve_upstream", return_value=fake_resp):
            h.handle(make_query("ext.com"))
        assert cache.get("ext.com", QType.A, QClass.IN) is None

    def test_log_queries_branch(self, cfg):
        cfg.server.log_queries = True
        h = DNSHandler(cfg, DNSCache())
        # Should not raise
        h.handle(make_query("web.test.lan"))

    def test_unsupported_qtype_forwarded_upstream(self, cfg):
        """Qtype not in RTYPE_MAP (e.g. type 99) should try upstream."""
        h = DNSHandler(cfg, DNSCache())
        fake_resp = DNSMessage(msg_id=42, flags=0x8180)
        with patch("nanodns.handler.resolve_upstream", return_value=fake_resp) as mock_up:
            h.handle(make_query("web.test.lan", qtype=99))
        mock_up.assert_called_once()

    def test_cache_ttl_capped_by_config(self, cfg):
        """Upstream TTL higher than cache_ttl should be capped."""
        cfg.server.cache_ttl = 10
        cache = DNSCache()
        h = DNSHandler(cfg, cache)
        fake_resp = DNSMessage(msg_id=42, flags=0x8180)
        fake_resp.answers.append(DNSRecord("ext.com", QType.A, QClass.IN, 9999, encode_a("1.1.1.1")))
        with patch("nanodns.handler.resolve_upstream", return_value=fake_resp):
            h.handle(make_query("ext.com"))
        entry = cache._cache.get("ext.com:1:1")
        assert entry is not None
        assert entry.remaining_ttl <= 11  # at most cache_ttl + 1s slack


# ═══════════════════════════════════════════════════════════════════════════════
# Resolver — mocked network
# ═══════════════════════════════════════════════════════════════════════════════

class TestResolver:

    def _make_query(self):
        msg = DNSMessage(msg_id=1, flags=0x0100)
        msg.questions.append(DNSQuestion("example.com", QType.A, QClass.IN))
        return msg

    def _fake_response(self) -> bytes:
        resp = DNSMessage(msg_id=1, flags=0x8180)
        resp.answers.append(DNSRecord("example.com", QType.A, QClass.IN, 300, encode_a("1.2.3.4")))
        return build_message(resp)

    def test_resolve_upstream_success(self):
        query = self._make_query()
        fake_data = self._fake_response()
        with patch("nanodns.resolver._query_udp") as mock_udp:
            mock_udp.return_value = parse_message(fake_data)
            result = resolve_upstream(query, ["8.8.8.8"], port=53, timeout=2)
        assert result is not None
        assert result.answers[0].rdata == encode_a("1.2.3.4")

    def test_resolve_upstream_first_fails_tries_second(self):
        query = self._make_query()
        fake_data = self._fake_response()
        responses = [Exception("timeout"), parse_message(fake_data)]
        with patch("nanodns.resolver._query_udp", side_effect=responses):
            result = resolve_upstream(query, ["8.8.8.8", "1.1.1.1"], port=53, timeout=2)
        assert result is not None

    def test_resolve_upstream_all_fail_returns_none(self):
        query = self._make_query()
        with patch("nanodns.resolver._query_udp", side_effect=Exception("timeout")):
            result = resolve_upstream(query, ["8.8.8.8", "1.1.1.1"], port=53, timeout=2)
        assert result is None

    def test_resolve_upstream_empty_server_list(self):
        result = resolve_upstream(self._make_query(), [], port=53, timeout=2)
        assert result is None

    def test_query_udp_sends_and_receives(self):
        """Mock socket to test _query_udp directly."""
        fake_data = self._fake_response()
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (fake_data, ("8.8.8.8", 53))
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("nanodns.resolver.socket.socket", return_value=mock_sock):
            result = _query_udp(b"\x00" * 12, "8.8.8.8", 53, 2.0)

        assert result is not None
        mock_sock.settimeout.assert_called_once_with(2.0)
        mock_sock.sendto.assert_called_once()

    def test_query_udp_timeout_raises(self):
        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.timeout("timed out")
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("nanodns.resolver.socket.socket", return_value=mock_sock):
            with pytest.raises(socket.timeout):
                _query_udp(b"\x00" * 12, "8.8.8.8", 53, 0.1)


# ═══════════════════════════════════════════════════════════════════════════════
# Server
# ═══════════════════════════════════════════════════════════════════════════════

class TestDNSServerProtocol:
    """
    DNSServerProtocol now holds a reference to DNSServer (not DNSHandler directly),
    so that apply_config() handler swaps are visible to the protocol immediately.

    Root-cause of the "stale records after reload" bug:
        Old: DNSServerProtocol(handler)  → self.handler captured at start-up time.
             apply_config() replaces DNSServer.handler but protocol keeps the old object.
        Fix: DNSServerProtocol(server)   → self.server.handler looked up on every packet.
    """

    # ── helpers ───────────────────────────────────────────────────────────────

    def _make_cfg(self, records=None, zone="t.lan"):
        return _parse_config({
            "server": {
                "host": "127.0.0.1", "port": 5353, "upstream": [],
                "log_queries": False, "hot_reload": False,
                "cache_enabled": True, "cache_ttl": 300, "cache_size": 100,
                "log_level": "WARNING", "upstream_timeout": 2, "upstream_port": 53,
            },
            "zones": {zone: {}},
            "records": records or [
                {"name": "a.t.lan", "type": "A", "value": "1.2.3.4", "ttl": 60}
            ],
            "rewrites": [],
        }, None)

    def _make_server(self, records=None):
        from nanodns.server import DNSServer
        return DNSServer(self._make_cfg(records))

    # ── construction ──────────────────────────────────────────────────────────

    def test_protocol_holds_server_not_handler(self):
        """Protocol must store a DNSServer reference, not a bare DNSHandler.

        If this fails, the apply_config() fix was reverted — stale-record bug
        will reappear.
        """
        from nanodns.server import DNSServerProtocol, DNSServer
        server = self._make_server()
        proto = DNSServerProtocol(server)
        assert hasattr(proto, "server"), "proto must expose .server"
        assert isinstance(proto.server, DNSServer), "proto.server must be a DNSServer"
        assert not hasattr(proto, "handler") or proto.handler is None, (
            "proto must NOT cache handler directly — that caused the stale-record bug"
        )

    def test_connection_made_sets_transport(self):
        from nanodns.server import DNSServerProtocol
        proto = DNSServerProtocol(self._make_server())
        transport = MagicMock()
        proto.connection_made(transport)
        assert proto.transport is transport

    # ── normal query dispatch ─────────────────────────────────────────────────

    def test_datagram_received_sends_response(self):
        from nanodns.server import DNSServerProtocol
        proto = DNSServerProtocol(self._make_server())
        proto.transport = MagicMock()

        msg = DNSMessage(msg_id=1, flags=0x0100)
        msg.questions.append(DNSQuestion("a.t.lan", QType.A, QClass.IN))
        proto.datagram_received(build_message(msg), ("127.0.0.1", 1234))

        proto.transport.sendto.assert_called_once()
        raw = proto.transport.sendto.call_args[0][0]
        assert isinstance(raw, bytes) and len(raw) > 0

    def test_datagram_received_empty_response_not_sent(self):
        from nanodns.server import DNSServerProtocol
        proto = DNSServerProtocol(self._make_server())
        proto.transport = MagicMock()
        proto.datagram_received(b"\x00\x01", ("127.0.0.1", 1234))  # malformed
        proto.transport.sendto.assert_not_called()

    def test_datagram_received_handler_exception_logged(self):
        """Exception inside handler.handle() must be caught and logged, not propagated."""
        from nanodns.server import DNSServerProtocol, DNSServer
        server = self._make_server()
        server.handler = MagicMock()
        server.handler.handle.side_effect = RuntimeError("boom")
        proto = DNSServerProtocol(server)
        proto.transport = MagicMock()
        proto.datagram_received(b"\x00" * 12, ("127.0.0.1", 1234))  # must not raise
        proto.transport.sendto.assert_not_called()

    def test_error_received_logs(self):
        from nanodns.server import DNSServerProtocol
        proto = DNSServerProtocol(self._make_server())
        proto.error_received(OSError("network error"))  # must not raise

    # ── THE critical regression test ──────────────────────────────────────────

    def test_protocol_uses_handler_after_apply_config(self):
        """After apply_config(), the protocol must serve records from the NEW config.

        This is the exact scenario that was broken:
          1. Server starts with record  db.t.lan → 1.1.1.1
          2. Config reloaded → db.t.lan → 2.2.2.2  (apply_config swaps DNSServer.handler)
          3. Protocol receives a query for db.t.lan
          4. EXPECTED: response contains 2.2.2.2
          5. BUG (before fix): response still contained 1.1.1.1 because the
             protocol held the old handler object and never saw the swap.
        """
        from nanodns.server import DNSServerProtocol, DNSServer

        # --- v1 config: db.t.lan → 1.1.1.1 ---
        server = self._make_server(records=[
            {"name": "db.t.lan", "type": "A", "value": "1.1.1.1", "ttl": 60}
        ])
        proto = DNSServerProtocol(server)
        proto.transport = MagicMock()

        def query_db():
            proto.transport.reset_mock()
            msg = DNSMessage(msg_id=1, flags=0x0100)
            msg.questions.append(DNSQuestion("db.t.lan", QType.A, QClass.IN))
            proto.datagram_received(build_message(msg), ("127.0.0.1", 1234))
            raw = proto.transport.sendto.call_args[0][0]
            return parse_message(raw)

        resp_before = query_db()
        assert resp_before.answers[0].rdata == encode_a("1.1.1.1"), (
            "pre-condition: v1 record should return 1.1.1.1"
        )

        # --- apply_config: db.t.lan → 2.2.2.2 ---
        new_cfg = self._make_cfg(records=[
            {"name": "db.t.lan", "type": "A", "value": "2.2.2.2", "ttl": 60}
        ])
        server.apply_config(new_cfg)   # swaps server.handler in-place

        resp_after = query_db()
        assert resp_after.answers[0].rdata == encode_a("2.2.2.2"), (
            "REGRESSION: protocol returned stale 1.1.1.1 after apply_config(); "
            "protocol must read handler via self.server.handler, not a cached reference"
        )


class TestDNSServer:

    def _cfg(self, **overrides):
        base = {
            "server": {"host": "127.0.0.1", "port": 5353, "upstream": [],
                       "log_queries": False, "hot_reload": False,
                       "cache_enabled": True, "cache_ttl": 300, "cache_size": 50,
                       "log_level": "WARNING", "upstream_timeout": 2, "upstream_port": 53},
            "zones": {}, "records": [], "rewrites": [],
        }
        base["server"].update(overrides)
        return _parse_config(base, None)

    def test_init_creates_handler_and_cache(self):
        from nanodns.server import DNSServer
        server = DNSServer(self._cfg())
        assert server.cache is not None
        assert server.handler is not None
        assert server._running is False

    def test_cache_stats(self):
        from nanodns.server import DNSServer
        server = DNSServer(self._cfg())
        stats = server.cache_stats()
        assert "size" in stats and "hits" in stats

    def test_reload_config_success(self, tmp_path):
        from nanodns.server import DNSServer
        import json
        p = tmp_path / "cfg.json"
        data = {
            "server": {"host": "127.0.0.1", "port": 5353, "upstream": [],
                       "log_queries": False, "hot_reload": True,
                       "cache_enabled": True, "cache_ttl": 60, "cache_size": 50,
                       "log_level": "WARNING", "upstream_timeout": 2, "upstream_port": 53},
            "zones": {}, "records": [], "rewrites": [],
        }
        p.write_text(json.dumps(data))
        cfg = _parse_config(data, p)
        server = DNSServer(cfg)
        server.reload_config(str(p))
        assert server.config is not None

    def test_reload_config_bad_path_logs_error(self):
        from nanodns.server import DNSServer
        server = DNSServer(self._cfg())
        # Should not raise — just log the error
        server.reload_config("/nonexistent/path.json")

    def test_start_and_stop(self):
        """Start the server on a random port and immediately cancel it."""
        from nanodns.server import DNSServer
        import asyncio

        async def run():
            server = DNSServer(self._cfg(port=0))
            task = asyncio.create_task(server.start())
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(run())

    def test_watch_config_reloads_when_stale(self, tmp_path):
        """_watch_config calls reload_config when config is stale."""
        import asyncio, json
        from nanodns.server import DNSServer

        data = {
            "server": {"host": "127.0.0.1", "port": 5353, "upstream": [],
                       "log_queries": False, "hot_reload": True,
                       "cache_enabled": True, "cache_ttl": 60, "cache_size": 50,
                       "log_level": "WARNING", "upstream_timeout": 2, "upstream_port": 53},
            "zones": {}, "records": [], "rewrites": [],
        }
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps(data))
        cfg = _parse_config(data, p)
        server = DNSServer(cfg)
        server._running = True

        reloaded = []
        def mock_reload(path=None):
            reloaded.append(True)
            server._running = False
        server.reload_config = mock_reload
        server.config._mtime = 0.0
        server.config.server.hot_reload = True

        async def fast_sleep(t): pass

        async def run():
            with patch("asyncio.sleep", side_effect=fast_sleep):
                await server._watch_config()

        asyncio.run(run())
        assert len(reloaded) == 1

    def test_prune_cache_runs(self):
        """_prune_cache prunes and logs stats."""
        import asyncio
        from nanodns.server import DNSServer

        server = DNSServer(self._cfg())
        server._running = True
        call_count = [0]

        async def run():
            original_sleep = asyncio.sleep
            async def mock_sleep(t):
                call_count[0] += 1
                server._running = False  # stop after first iteration
            with patch("asyncio.sleep", side_effect=mock_sleep):
                await server._prune_cache()

        asyncio.run(run())
        assert call_count[0] == 1


class TestSetupLogging:

    def test_setup_logging_info(self):
        from nanodns.server import setup_logging
        setup_logging("INFO")   # should not raise

    def test_setup_logging_debug(self):
        from nanodns.server import setup_logging
        setup_logging("DEBUG")

    def test_setup_logging_invalid_falls_back(self):
        from nanodns.server import setup_logging
        setup_logging("NOTAREAL")  # getattr fallback → logging.INFO


class TestRunServer:

    def test_run_server_stops_on_event(self):
        """run_server cancels cleanly when stop_event fires."""
        import asyncio
        from nanodns.server import run_server
        from nanodns.config import _parse_config

        cfg = _parse_config({
            "server": {"host": "127.0.0.1", "port": 0, "upstream": [],
                       "log_queries": False, "hot_reload": False,
                       "cache_enabled": False, "cache_ttl": 60, "cache_size": 50,
                       "log_level": "WARNING", "upstream_timeout": 2, "upstream_port": 53},
            "zones": {}, "records": [], "rewrites": [],
        }, None)

        async def run():
            task = asyncio.create_task(run_server(cfg))
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(run())


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

class TestCLI:

    def _run(self, args: list[str]) -> tuple[int, str, str]:
        """Run CLI main() with given argv, capturing stdout/stderr and exit code."""
        import io
        from nanodns.cli import main

        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        exit_code = 0

        with patch("sys.argv", ["nanodns"] + args), \
             patch("sys.stdout", stdout_buf), \
             patch("sys.stderr", stderr_buf):
            try:
                main()
            except SystemExit as e:
                exit_code = int(e.code) if e.code is not None else 0

        return exit_code, stdout_buf.getvalue(), stderr_buf.getvalue()

    # ── init ──────────────────────────────────────────────────────────────────

    def test_init_default_path(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        code, out, _ = self._run(["init"])
        assert code == 0
        assert (tmp_path / "nanodns.json").exists()

    def test_init_custom_path(self, tmp_path):
        out_file = str(tmp_path / "custom.json")
        code, _, _ = self._run(["init", out_file])
        assert code == 0
        import json
        data = json.loads(open(out_file).read())
        assert "server" in data

    # ── check ─────────────────────────────────────────────────────────────────

    def test_check_valid_config(self, tmp_path):
        import json
        cfg_file = tmp_path / "cfg.json"
        cfg_file.write_text(json.dumps({
            "server": {"host": "0.0.0.0", "port": 5353, "upstream": ["8.8.8.8"],
                       "log_queries": False, "hot_reload": False,
                       "cache_enabled": True, "cache_ttl": 300, "cache_size": 100,
                       "log_level": "INFO", "upstream_timeout": 3, "upstream_port": 53},
            "zones": {}, "records": [], "rewrites": [],
        }))
        code, out, _ = self._run(["check", str(cfg_file)])
        assert code == 0
        assert "valid" in out.lower() or "✓" in out

    def test_check_missing_file(self, tmp_path):
        code, _, err = self._run(["check", str(tmp_path / "missing.json")])
        assert code != 0

    def test_check_invalid_json(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{ not valid json }")
        code, _, err = self._run(["check", str(bad)])
        assert code != 0

    # ── start ─────────────────────────────────────────────────────────────────

    def test_start_missing_config_file(self, tmp_path):
        code, _, err = self._run(["start", "--config", str(tmp_path / "missing.json")])
        assert code != 0

    def test_start_invalid_config(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{ bad }")
        code, _, err = self._run(["start", "--config", str(bad)])
        assert code != 0

    def test_start_applies_cli_overrides(self, tmp_path):
        import json, asyncio
        cfg_file = tmp_path / "cfg.json"
        cfg_file.write_text(json.dumps({
            "server": {"host": "0.0.0.0", "port": 5353, "upstream": [],
                       "log_queries": False, "hot_reload": False,
                       "cache_enabled": True, "cache_ttl": 300, "cache_size": 100,
                       "log_level": "INFO", "upstream_timeout": 3, "upstream_port": 53},
            "zones": {}, "records": [], "rewrites": [],
        }))
        captured = {}

        async def fake_run_server(cfg):
            captured["host"] = cfg.server.host
            captured["port"] = cfg.server.port
            captured["log_level"] = cfg.server.log_level
            captured["cache"] = cfg.server.cache_enabled

        with patch("nanodns.cli.run_server", side_effect=fake_run_server), \
             patch("nanodns.cli.setup_logging"):
            self._run([
                "start", "--config", str(cfg_file),
                "--host", "192.168.1.1",
                "--port", "5353",
                "--log-level", "DEBUG",
                "--no-cache",
            ])

        assert captured.get("host") == "192.168.1.1"
        assert captured.get("port") == 5353
        assert captured.get("log_level") == "DEBUG"
        assert captured.get("cache") is False

    def test_start_default_config_no_overrides(self, tmp_path):
        import json
        cfg_file = tmp_path / "cfg.json"
        cfg_file.write_text(json.dumps({
            "server": {"host": "0.0.0.0", "port": 5353, "upstream": [],
                       "log_queries": False, "hot_reload": False,
                       "cache_enabled": True, "cache_ttl": 300, "cache_size": 100,
                       "log_level": "INFO", "upstream_timeout": 3, "upstream_port": 53},
            "zones": {}, "records": [], "rewrites": [],
        }))
        captured = {}

        async def fake_run_server(cfg):
            captured["host"] = cfg.server.host
            captured["cache"] = cfg.server.cache_enabled

        with patch("nanodns.cli.run_server", side_effect=fake_run_server), \
             patch("nanodns.cli.setup_logging"):
            self._run(["start", "--config", str(cfg_file)])

        assert captured.get("host") == "0.0.0.0"
        assert captured.get("cache") is True

    def test_start_keyboard_interrupt_handled(self, tmp_path):
        import json
        cfg_file = tmp_path / "cfg.json"
        cfg_file.write_text(json.dumps({
            "server": {"host": "0.0.0.0", "port": 5353, "upstream": [],
                       "log_queries": False, "hot_reload": False,
                       "cache_enabled": True, "cache_ttl": 300, "cache_size": 100,
                       "log_level": "INFO", "upstream_timeout": 3, "upstream_port": 53},
            "zones": {}, "records": [], "rewrites": [],
        }))

        async def fake_run_server(cfg):
            raise KeyboardInterrupt

        with patch("nanodns.cli.run_server", side_effect=fake_run_server), \
             patch("nanodns.cli.setup_logging"):
            code, _, _ = self._run(["start", "--config", str(cfg_file)])
        # KeyboardInterrupt should be swallowed, not crash
        assert code == 0

    def test_start_port_warning_low_port(self, tmp_path):
        """port < 1024 triggers privilege warning branch."""
        import json
        cfg_file = tmp_path / "cfg.json"
        cfg_file.write_text(json.dumps({
            "server": {"host": "0.0.0.0", "port": 53, "upstream": [],
                       "log_queries": False, "hot_reload": False,
                       "cache_enabled": True, "cache_ttl": 300, "cache_size": 100,
                       "log_level": "INFO", "upstream_timeout": 3, "upstream_port": 53},
            "zones": {}, "records": [], "rewrites": [],
        }))

        async def fake_run_server(cfg):
            pass

        # Force non-admin path
        with patch("nanodns.cli.run_server", side_effect=fake_run_server), \
             patch("nanodns.cli.setup_logging"), \
             patch("os.geteuid", return_value=1000):  # non-root
            self._run(["start", "--config", str(cfg_file)])
        # No assertion needed — just ensure it doesn't crash

    def test_start_port_warning_windows_path(self, tmp_path):
        """Simulate Windows where os.geteuid doesn't exist."""
        import json
        cfg_file = tmp_path / "cfg.json"
        cfg_file.write_text(json.dumps({
            "server": {"host": "0.0.0.0", "port": 53, "upstream": [],
                       "log_queries": False, "hot_reload": False,
                       "cache_enabled": True, "cache_ttl": 300, "cache_size": 100,
                       "log_level": "INFO", "upstream_timeout": 3, "upstream_port": 53},
            "zones": {}, "records": [], "rewrites": [],
        }))

        async def fake_run_server(cfg):
            pass

        # Simulate missing geteuid (Windows)
        import os as _os
        with patch("nanodns.cli.run_server", side_effect=fake_run_server), \
             patch("nanodns.cli.setup_logging"), \
             patch.object(_os, "geteuid", side_effect=AttributeError, create=True):
            self._run(["start", "--config", str(cfg_file)])
