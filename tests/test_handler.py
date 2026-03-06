"""
Unit tests for nanodns.handler and nanodns.resolver
Covers: encode_record (all types), DNSHandler (all query paths),
        resolve_upstream (mocked network), _query_udp.
"""

import os
import socket
import sys
from unittest.mock import MagicMock, patch
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nanodns.protocol import (
    DNSMessage, DNSQuestion, DNSRecord,
    QType, QClass,
    encode_a, encode_aaaa, encode_cname, encode_txt,
    encode_mx, encode_ns, encode_ptr,
    parse_message, build_message,
)
from nanodns.config import _parse_config, RecordEntry
from nanodns.cache import DNSCache
from nanodns.handler import (
    DNSHandler, encode_record,
    RCODE_FORMERR, RCODE_SERVFAIL, RCODE_NXDOMAIN,
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


@pytest.fixture
def handler(cfg):
    return DNSHandler(cfg, DNSCache())


def make_query(name: str, qtype: int = QType.A, msg_id: int = 42) -> bytes:
    msg = DNSMessage(msg_id=msg_id, flags=0x0100)
    msg.questions.append(DNSQuestion(name=name, qtype=qtype, qclass=QClass.IN))
    return build_message(msg)


# ═══════════════════════════════════════════════════════════════════════════════
# encode_record
# ═══════════════════════════════════════════════════════════════════════════════

class TestEncodeRecord:

    def _rec(self, rtype, value, priority=10):
        return RecordEntry(name="test", rtype=rtype, value=value,
                           ttl=300, priority=priority)

    def test_a(self):
        assert encode_record(self._rec("A",     "1.2.3.4"))   == encode_a("1.2.3.4")

    def test_aaaa(self):
        assert encode_record(self._rec("AAAA",  "::1"))        == encode_aaaa("::1")

    def test_cname(self):
        assert encode_record(self._rec("CNAME", "target.lan")) == encode_cname("target.lan")

    def test_ptr(self):
        assert encode_record(self._rec("PTR",   "host.lan"))   == encode_ptr("host.lan")

    def test_ns(self):
        assert encode_record(self._rec("NS",    "ns1.lan"))    == encode_ns("ns1.lan")

    def test_mx(self):
        assert encode_record(self._rec("MX",    "mail.lan", 20)) == encode_mx(20, "mail.lan")

    def test_txt(self):
        assert encode_record(self._rec("TXT",   "hello"))     == encode_txt("hello")

    def test_unsupported_type_returns_none(self):
        assert encode_record(self._rec("UNKNOWN", "value")) is None

    def test_bad_ip_returns_none(self):
        assert encode_record(self._rec("A", "not-an-ip")) is None

    def test_lowercase_type(self):
        assert encode_record(self._rec("a", "1.2.3.4")) == encode_a("1.2.3.4")


# ═══════════════════════════════════════════════════════════════════════════════
# DNSHandler — local record responses
# ═══════════════════════════════════════════════════════════════════════════════

class TestHandlerLocalRecords:

    def test_a_multi(self, handler):
        resp = parse_message(handler.handle(make_query("web.test.lan")))
        assert resp.rcode == 0 and len(resp.answers) == 2

    def test_aaaa(self, handler):
        resp = parse_message(handler.handle(make_query("ipv6.test.lan", QType.AAAA)))
        assert resp.answers[0].rdata == encode_aaaa("fd00::1")

    def test_cname(self, handler):
        assert parse_message(handler.handle(make_query("api.test.lan", QType.CNAME))).rcode == 0

    def test_mx_multi(self, handler):
        resp = parse_message(handler.handle(make_query("test.lan", QType.MX)))
        assert resp.rcode == 0 and len(resp.answers) == 2

    def test_txt(self, handler):
        assert parse_message(handler.handle(make_query("test.lan", QType.TXT))).rcode == 0

    def test_ns(self, handler):
        assert parse_message(handler.handle(make_query("test.lan", QType.NS))).rcode == 0

    def test_ptr(self, handler):
        assert parse_message(
            handler.handle(make_query("1.0.0.10.in-addr.arpa", QType.PTR))
        ).rcode == 0

    def test_soa(self, handler):
        resp = parse_message(handler.handle(make_query("test.lan", QType.SOA)))
        assert resp.rcode == 0 and len(resp.answers) == 1

    def test_any_returns_multiple(self, handler):
        resp = parse_message(handler.handle(make_query("test.lan", QType.ANY)))
        assert resp.rcode == 0 and len(resp.answers) > 0

    def test_wildcard_resolves(self, handler):
        resp = parse_message(handler.handle(make_query("foo.app.test.lan")))
        assert resp.answers[0].rdata == encode_a("10.0.1.1")

    def test_msg_id_echoed(self, handler):
        resp = parse_message(handler.handle(make_query("web.test.lan", msg_id=9999)))
        assert resp.msg_id == 9999

    def test_response_flag_set(self, handler):
        assert parse_message(handler.handle(make_query("web.test.lan"))).is_response

    def test_log_queries_branch(self, cfg):
        cfg.server.log_queries = True
        DNSHandler(cfg, DNSCache()).handle(make_query("web.test.lan"))  # must not raise


# ═══════════════════════════════════════════════════════════════════════════════
# DNSHandler — NXDOMAIN and rewrites
# ═══════════════════════════════════════════════════════════════════════════════

class TestHandlerNXDomainAndRewrites:

    def test_nxdomain_in_zone(self, handler):
        assert parse_message(handler.handle(make_query("ghost.test.lan"))).rcode == RCODE_NXDOMAIN

    def test_nxdomain_zone_apex_no_a_record(self, handler):
        assert parse_message(handler.handle(make_query("test.lan", QType.A))).rcode == RCODE_NXDOMAIN

    def test_rewrite_exact(self, handler):
        assert parse_message(handler.handle(make_query("blocked.com"))).rcode == RCODE_NXDOMAIN

    def test_rewrite_wildcard(self, handler):
        assert parse_message(handler.handle(make_query("t.ads.example"))).rcode == RCODE_NXDOMAIN


# ═══════════════════════════════════════════════════════════════════════════════
# DNSHandler — error paths
# ═══════════════════════════════════════════════════════════════════════════════

class TestHandlerErrorPaths:

    def test_no_questions_returns_formerr(self, handler):
        raw = build_message(DNSMessage(msg_id=1, flags=0x0100))
        assert parse_message(handler.handle(raw)).rcode == RCODE_FORMERR

    def test_malformed_bytes_returns_empty(self, handler):
        assert handler.handle(b"\x00\x01\x02") == b""

    def test_empty_bytes_returns_empty(self, handler):
        assert handler.handle(b"") == b""

    def test_no_upstream_returns_servfail(self, cfg):
        cfg.server.upstream = []
        resp = parse_message(DNSHandler(cfg, DNSCache()).handle(make_query("external.com")))
        assert resp.rcode == RCODE_SERVFAIL

    def test_upstream_none_returns_servfail(self, cfg):
        with patch("nanodns.handler.resolve_upstream", return_value=None):
            resp = parse_message(DNSHandler(cfg, DNSCache()).handle(make_query("ext.com")))
        assert resp.rcode == RCODE_SERVFAIL

    def test_unsupported_qtype_forwarded_upstream(self, cfg):
        fake = DNSMessage(msg_id=42, flags=0x8180)
        with patch("nanodns.handler.resolve_upstream", return_value=fake) as mock_up:
            DNSHandler(cfg, DNSCache()).handle(make_query("web.test.lan", qtype=99))
        mock_up.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# DNSHandler — caching integration
# ═══════════════════════════════════════════════════════════════════════════════

class TestHandlerCaching:

    def test_cache_hit_served(self, cfg):
        cache = DNSCache()
        dummy = DNSMessage(msg_id=1, flags=0x8180)
        dummy.answers.append(
            DNSRecord("cached.com", QType.A, QClass.IN, 300, encode_a("9.9.9.9"))
        )
        cache.set("cached.com", QType.A, QClass.IN, dummy, ttl=60)
        resp = parse_message(DNSHandler(cfg, cache).handle(make_query("cached.com")))
        assert resp.answers[0].rdata == encode_a("9.9.9.9")
        assert cache.stats["hits"] == 1

    def test_upstream_response_cached(self, cfg):
        cache = DNSCache()
        fake = DNSMessage(msg_id=42, flags=0x8180)
        fake.answers.append(
            DNSRecord("ext.com", QType.A, QClass.IN, 60, encode_a("1.1.1.1"))
        )
        with patch("nanodns.handler.resolve_upstream", return_value=fake):
            DNSHandler(cfg, cache).handle(make_query("ext.com"))
        assert cache.get("ext.com", QType.A, QClass.IN) is not None

    def test_empty_upstream_answer_not_cached(self, cfg):
        cache = DNSCache()
        fake = DNSMessage(msg_id=42, flags=0x8180)  # no answers
        with patch("nanodns.handler.resolve_upstream", return_value=fake):
            DNSHandler(cfg, cache).handle(make_query("ext.com"))
        assert cache.get("ext.com", QType.A, QClass.IN) is None

    def test_cache_disabled_upstream_not_cached(self, cfg):
        cfg.server.cache_enabled = False
        cache = DNSCache()
        fake = DNSMessage(msg_id=42, flags=0x8180)
        fake.answers.append(
            DNSRecord("ext.com", QType.A, QClass.IN, 60, encode_a("1.1.1.1"))
        )
        with patch("nanodns.handler.resolve_upstream", return_value=fake):
            DNSHandler(cfg, cache).handle(make_query("ext.com"))
        assert cache.get("ext.com", QType.A, QClass.IN) is None

    def test_upstream_ttl_capped_by_config(self, cfg):
        cfg.server.cache_ttl = 10
        cache = DNSCache()
        fake = DNSMessage(msg_id=42, flags=0x8180)
        fake.answers.append(
            DNSRecord("ext.com", QType.A, QClass.IN, 9999, encode_a("1.1.1.1"))
        )
        with patch("nanodns.handler.resolve_upstream", return_value=fake):
            DNSHandler(cfg, cache).handle(make_query("ext.com"))
        entry = cache._cache.get("ext.com:1:1")
        assert entry is not None
        assert entry.remaining_ttl <= 11   # at most cache_ttl + 1 s slack


# ═══════════════════════════════════════════════════════════════════════════════
# Resolver (mocked network)
# ═══════════════════════════════════════════════════════════════════════════════

class TestResolver:

    def _query(self):
        msg = DNSMessage(msg_id=1, flags=0x0100)
        msg.questions.append(DNSQuestion("example.com", QType.A, QClass.IN))
        return msg

    def _response_bytes(self) -> bytes:
        resp = DNSMessage(msg_id=1, flags=0x8180)
        resp.answers.append(
            DNSRecord("example.com", QType.A, QClass.IN, 300, encode_a("1.2.3.4"))
        )
        return build_message(resp)

    def test_success(self):
        with patch("nanodns.resolver._query_udp") as mock:
            mock.return_value = parse_message(self._response_bytes())
            result = resolve_upstream(self._query(), ["8.8.8.8"], port=53, timeout=2)
        assert result is not None
        assert result.answers[0].rdata == encode_a("1.2.3.4")

    def test_first_fails_tries_second(self):
        responses = [Exception("timeout"), parse_message(self._response_bytes())]
        with patch("nanodns.resolver._query_udp", side_effect=responses):
            result = resolve_upstream(self._query(), ["8.8.8.8", "1.1.1.1"], port=53, timeout=2)
        assert result is not None

    def test_all_fail_returns_none(self):
        with patch("nanodns.resolver._query_udp", side_effect=Exception("timeout")):
            result = resolve_upstream(self._query(), ["8.8.8.8", "1.1.1.1"], port=53, timeout=2)
        assert result is None

    def test_empty_server_list_returns_none(self):
        assert resolve_upstream(self._query(), [], port=53, timeout=2) is None

    def test_query_udp_sends_and_receives(self):
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (self._response_bytes(), ("8.8.8.8", 53))
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
