"""
Unit tests for nanodns.cache
Covers: set/get, TTL expiry, LRU eviction, invalidate, clear, prune, stats,
        thread safety.
"""

import os
import sys
import time
import threading
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nanodns.protocol import DNSMessage, QType, QClass
from nanodns.cache import DNSCache


def _msg(mid: int = 1) -> DNSMessage:
    return DNSMessage(msg_id=mid, flags=0x8180)


# ═══════════════════════════════════════════════════════════════════════════════
# Basic set / get
# ═══════════════════════════════════════════════════════════════════════════════

class TestCacheSetGet:

    def test_set_then_get(self):
        c = DNSCache()
        c.set("x.com", QType.A, QClass.IN, _msg(1), ttl=60)
        assert c.get("x.com", QType.A, QClass.IN).msg_id == 1

    def test_miss_returns_none(self):
        assert DNSCache().get("z.com", QType.A, QClass.IN) is None

    def test_different_qtypes_isolated(self):
        c = DNSCache()
        c.set("x.com", QType.A, QClass.IN, _msg(1), ttl=60)
        assert c.get("x.com", QType.AAAA, QClass.IN) is None

    def test_case_insensitive_key(self):
        c = DNSCache()
        c.set("X.COM", QType.A, QClass.IN, _msg(1), ttl=60)
        assert c.get("x.com", QType.A, QClass.IN) is not None

    def test_overwrite_existing_key(self):
        c = DNSCache()
        c.set("x.com", QType.A, QClass.IN, _msg(1), ttl=60)
        c.set("x.com", QType.A, QClass.IN, _msg(2), ttl=60)
        assert c.get("x.com", QType.A, QClass.IN).msg_id == 2

    def test_ttl_zero_skips_storage(self):
        c = DNSCache()
        c.set("x.com", QType.A, QClass.IN, _msg(), ttl=0)
        assert c.get("x.com", QType.A, QClass.IN) is None

    def test_remaining_ttl_within_range(self):
        c = DNSCache()
        c.set("a.com", QType.A, QClass.IN, _msg(), ttl=60)
        key = list(c._cache.keys())[0]
        assert 58 <= c._cache[key].remaining_ttl <= 60


# ═══════════════════════════════════════════════════════════════════════════════
# Expiry
# ═══════════════════════════════════════════════════════════════════════════════

class TestCacheExpiry:

    def test_expired_entry_removed_on_get(self):
        c = DNSCache()
        c.set("x.com", QType.A, QClass.IN, _msg(), ttl=60)
        key = list(c._cache.keys())[0]
        c._cache[key].expires_at = time.monotonic() - 1
        assert c.get("x.com", QType.A, QClass.IN) is None

    def test_prune_removes_expired_only(self):
        c = DNSCache()
        c.set("old.com", QType.A, QClass.IN, _msg(), ttl=60)
        c.set("new.com", QType.A, QClass.IN, _msg(), ttl=60)
        c._cache["old.com:1:1"].expires_at = time.monotonic() - 1
        c.prune()
        assert c.stats["size"] == 1
        assert c.get("new.com", QType.A, QClass.IN) is not None


# ═══════════════════════════════════════════════════════════════════════════════
# LRU eviction
# ═══════════════════════════════════════════════════════════════════════════════

class TestCacheLRU:

    def test_eviction_respects_max_size(self):
        c = DNSCache(max_size=3)
        for i in range(5):
            c.set(f"h{i}.com", QType.A, QClass.IN, _msg(i), ttl=60)
        assert c.stats["size"] == 3

    def test_access_order_preserved(self):
        c = DNSCache(max_size=3)
        for name in ("a.com", "b.com", "c.com"):
            c.set(name, QType.A, QClass.IN, _msg(), ttl=60)
        c.get("a.com", QType.A, QClass.IN)   # touch a → b is now LRU
        c.set("d.com", QType.A, QClass.IN, _msg(), ttl=60)   # evicts b
        assert c.get("b.com", QType.A, QClass.IN) is None
        assert c.get("a.com", QType.A, QClass.IN) is not None


# ═══════════════════════════════════════════════════════════════════════════════
# Invalidate / clear
# ═══════════════════════════════════════════════════════════════════════════════

class TestCacheInvalidation:

    def test_invalidate_removes_all_qtypes_for_name(self):
        c = DNSCache()
        c.set("w.com", QType.A,    QClass.IN, _msg(), ttl=60)
        c.set("w.com", QType.AAAA, QClass.IN, _msg(), ttl=60)
        c.invalidate("w.com")
        assert c.get("w.com", QType.A,    QClass.IN) is None
        assert c.get("w.com", QType.AAAA, QClass.IN) is None

    def test_clear_empties_cache(self):
        c = DNSCache()
        for i in range(5):
            c.set(f"h{i}.com", QType.A, QClass.IN, _msg(), ttl=60)
        c.clear()
        assert c.stats["size"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Stats
# ═══════════════════════════════════════════════════════════════════════════════

class TestCacheStats:

    def test_hit_rate_50(self):
        c = DNSCache()
        c.set("a.com", QType.A, QClass.IN, _msg(), ttl=60)
        c.get("a.com", QType.A, QClass.IN)   # hit
        c.get("b.com", QType.A, QClass.IN)   # miss
        s = c.stats
        assert s["hits"] == 1 and s["misses"] == 1
        assert s["hit_rate"] == pytest.approx(50.0)

    def test_hit_rate_zero_requests(self):
        assert DNSCache().stats["hit_rate"] == 0.0

    def test_hit_rate_all_hits(self):
        c = DNSCache()
        c.set("a.com", QType.A, QClass.IN, _msg(), ttl=60)
        c.get("a.com", QType.A, QClass.IN)
        c.get("a.com", QType.A, QClass.IN)
        assert c.stats["hit_rate"] == 100.0


# ═══════════════════════════════════════════════════════════════════════════════
# Thread safety
# ═══════════════════════════════════════════════════════════════════════════════

class TestCacheThreadSafety:

    def test_concurrent_reads_writes(self):
        c = DNSCache(max_size=50)
        errors = []

        def worker(i):
            try:
                c.set(f"h{i}.com", QType.A, QClass.IN, DNSMessage(i, 0x8180), ttl=60)
                c.get(f"h{i}.com", QType.A, QClass.IN)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert errors == []
