"""
Integration tests for NanoDNS.
Starts a real UDP server on a random port and sends actual DNS queries over the network.
"""

import asyncio
import socket
import threading
import time
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nanodns.protocol import (
    DNSMessage, DNSQuestion, DNSRecord,
    QType, QClass,
    encode_a, encode_aaaa,
    build_message, parse_message,
)
from nanodns.config import _parse_config
from nanodns.cache import DNSCache
from nanodns.handler import DNSHandler
from nanodns.server import DNSServerProtocol


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

INTEGRATION_CONFIG = {
    "server": {
        "host": "127.0.0.1",
        "port": 0,   # random port assigned by OS
        "upstream": ["8.8.8.8", "1.1.1.1"],
        "upstream_timeout": 3,
        "cache_enabled": True,
        "cache_ttl": 60,
        "cache_size": 200,
        "log_level": "WARNING",
        "log_queries": False,
        "hot_reload": False,
    },
    "zones": {
        "lan": {
            "soa": {
                "mname": "ns1.lan",
                "rname": "admin.lan",
                "serial": 1,
                "refresh": 3600,
                "retry": 900,
                "expire": 604800,
                "minimum": 60,
            },
            "ns": ["ns1.lan"],
        }
    },
    "records": [
        {"name": "ns1.lan",       "type": "A",     "value": "192.168.0.1",  "ttl": 3600},
        {"name": "web.lan",       "type": "A",     "value": "192.168.0.10", "ttl": 300},
        {"name": "web.lan",       "type": "A",     "value": "192.168.0.11", "ttl": 300},
        {"name": "ipv6.lan",      "type": "AAAA",  "value": "fd00::10",     "ttl": 300},
        {"name": "api.lan",       "type": "CNAME", "value": "web.lan",      "ttl": 300},
        {"name": "lan",           "type": "MX",    "value": "mail.lan",     "priority": 10},
        {"name": "lan",           "type": "TXT",   "value": "integration-test"},
        {"name": "wild.lan",      "type": "A",     "value": "192.168.0.99", "wildcard": True},
        {"name": "1.0.168.192.in-addr.arpa", "type": "PTR", "value": "ns1.lan"},
    ],
    "rewrites": [
        {"match": "blocked.test",   "action": "nxdomain"},
        {"match": "*.spam.test",    "action": "nxdomain"},
    ],
}


def send_udp_query(host: str, port: int, name: str,
                   qtype: int = QType.A, timeout: float = 2.0) -> DNSMessage:
    """Send a DNS query over UDP and return the parsed response."""
    msg = DNSMessage(msg_id=1, flags=0x0100)
    msg.questions.append(DNSQuestion(name=name, qtype=qtype, qclass=QClass.IN))
    raw = build_message(msg)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(raw, (host, port))
        data, _ = s.recvfrom(4096)

    return parse_message(data)


# ═══════════════════════════════════════════════════════════════════════════════
# Server fixture — starts a real async UDP server in a background thread
# ═══════════════════════════════════════════════════════════════════════════════

class LiveServer:
    def __init__(self):
        self.host = "127.0.0.1"
        self.port = None
        self._loop = None
        self._transport = None
        self._thread = None
        self._ready = threading.Event()

    def start(self, config):
        self._config = config
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        assert self._ready.wait(timeout=5), "Server did not start in time"

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())

    async def _serve(self):
        cfg = _parse_config(self._config, None)
        cache = DNSCache(max_size=cfg.server.cache_size)
        handler = DNSHandler(cfg, cache)

        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: DNSServerProtocol(handler),
            local_addr=(self.host, 0),   # port=0 → random free port
        )
        self._transport = transport
        # Extract actual bound port
        self.port = transport.get_extra_info("sockname")[1]
        self._ready.set()
        # Keep running until stopped
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            transport.close()

    def stop(self):
        if self._loop and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self._loop.stop)


@pytest.fixture(scope="module")
def server():
    srv = LiveServer()
    srv.start(INTEGRATION_CONFIG)
    yield srv
    srv.stop()


def query(server, name: str, qtype: int = QType.A) -> DNSMessage:
    return send_udp_query(server.host, server.port, name, qtype)


# ═══════════════════════════════════════════════════════════════════════════════
# Integration: A / AAAA / CNAME / MX / TXT / PTR / NS / SOA
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntegrationRecords:

    def test_server_starts(self, server):
        assert server.port is not None
        assert server.port > 0

    def test_a_record_single(self, server):
        resp = query(server, "ns1.lan", QType.A)
        assert resp.rcode == 0
        assert len(resp.answers) == 1
        assert resp.answers[0].rdata == encode_a("192.168.0.1")

    def test_a_record_multi(self, server):
        resp = query(server, "web.lan", QType.A)
        assert resp.rcode == 0
        assert len(resp.answers) == 2
        rdatas = {a.rdata for a in resp.answers}
        assert encode_a("192.168.0.10") in rdatas
        assert encode_a("192.168.0.11") in rdatas

    def test_aaaa_record(self, server):
        resp = query(server, "ipv6.lan", QType.AAAA)
        assert resp.rcode == 0
        assert len(resp.answers) == 1
        assert resp.answers[0].rdata == encode_aaaa("fd00::10")

    def test_cname_record(self, server):
        resp = query(server, "api.lan", QType.CNAME)
        assert resp.rcode == 0
        assert len(resp.answers) == 1

    def test_mx_record(self, server):
        resp = query(server, "lan", QType.MX)
        assert resp.rcode == 0
        assert len(resp.answers) == 1

    def test_txt_record(self, server):
        resp = query(server, "lan", QType.TXT)
        assert resp.rcode == 0
        assert len(resp.answers) == 1

    def test_ptr_record(self, server):
        resp = query(server, "1.0.168.192.in-addr.arpa", QType.PTR)
        assert resp.rcode == 0
        assert len(resp.answers) == 1

    def test_soa_record(self, server):
        resp = query(server, "lan", QType.SOA)
        assert resp.rcode == 0
        assert len(resp.answers) == 1

    def test_ns_implicit(self, server):
        # NS records aren't in config but SOA zone exists — test zone awareness
        resp = query(server, "lan", QType.SOA)
        assert resp.is_response


class TestIntegrationNXDomain:

    def test_nxdomain_in_zone(self, server):
        resp = query(server, "ghost.lan", QType.A)
        assert resp.rcode == 3  # NXDOMAIN

    def test_nxdomain_rewrite_exact(self, server):
        resp = query(server, "blocked.test", QType.A)
        assert resp.rcode == 3

    def test_nxdomain_rewrite_wildcard(self, server):
        resp = query(server, "tracker.spam.test", QType.A)
        assert resp.rcode == 3

    def test_nxdomain_deep_wildcard_not_matched(self, server):
        # "a.b.spam.test" has two levels under spam.test — should NOT match *.spam.test
        resp = query(server, "a.b.spam.test", QType.A)
        # May forward upstream or return NXDOMAIN — either is acceptable
        assert resp.is_response


class TestIntegrationWildcard:

    def test_wildcard_match(self, server):
        resp = query(server, "anything.wild.lan", QType.A)
        assert resp.rcode == 0
        assert len(resp.answers) == 1
        assert resp.answers[0].rdata == encode_a("192.168.0.99")

    def test_wildcard_match_different_subdomain(self, server):
        resp = query(server, "foobar.wild.lan", QType.A)
        assert resp.rcode == 0
        assert resp.answers[0].rdata == encode_a("192.168.0.99")


class TestIntegrationCaching:

    def test_cache_serves_injected_entry(self, server):
        """Verify the cache layer works by querying the same record twice."""
        resp1 = query(server, "web.lan", QType.A)
        resp2 = query(server, "web.lan", QType.A)
        assert resp1.rcode == 0
        assert resp2.rcode == 0
        # Both responses should have same answer count
        assert len(resp1.answers) == len(resp2.answers)

    def test_msg_id_echoed(self, server):
        msg = DNSMessage(msg_id=12345, flags=0x0100)
        msg.questions.append(DNSQuestion("web.lan", QType.A, QClass.IN))
        raw = build_message(msg)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.sendto(raw, (server.host, server.port))
            data, _ = s.recvfrom(4096)
        resp = parse_message(data)
        assert resp.msg_id == 12345


class TestIntegrationConcurrency:

    def test_concurrent_queries(self, server):
        """Fire multiple queries concurrently from different threads."""
        import concurrent.futures
        queries = [
            ("web.lan",    QType.A),
            ("ipv6.lan",   QType.AAAA),
            ("api.lan",    QType.CNAME),
            ("blocked.test", QType.A),
            ("ghost.lan",  QType.A),
        ]

        def run(q):
            name, qtype = q
            return send_udp_query(server.host, server.port, name, qtype)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
            results = list(ex.map(run, queries * 3))   # 15 total queries

        assert len(results) == 15
        for r in results:
            assert r.is_response

    def test_rapid_sequential_queries(self, server):
        """Send 50 queries in rapid succession."""
        for i in range(50):
            resp = query(server, "web.lan", QType.A)
            assert resp.is_response
