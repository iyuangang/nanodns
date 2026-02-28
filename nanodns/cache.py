"""
Thread-safe DNS response cache with TTL expiry and LRU eviction.
"""

import time
import threading
from collections import OrderedDict
from typing import Optional
from .protocol import DNSMessage


class CacheEntry:
    __slots__ = ("message", "expires_at")

    def __init__(self, message: DNSMessage, ttl: int):
        self.message = message
        self.expires_at = time.monotonic() + ttl

    @property
    def is_expired(self) -> bool:
        return time.monotonic() >= self.expires_at

    @property
    def remaining_ttl(self) -> int:
        return max(0, int(self.expires_at - time.monotonic()))


class DNSCache:
    def __init__(self, max_size: int = 1000):
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        self._max_size = max_size
        self._hits = 0
        self._misses = 0

    def _make_key(self, name: str, qtype: int, qclass: int) -> str:
        return f"{name.lower().rstrip('.')}:{qtype}:{qclass}"

    def get(self, name: str, qtype: int, qclass: int) -> Optional[DNSMessage]:
        key = self._make_key(name, qtype, qclass)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None
            if entry.is_expired:
                del self._cache[key]
                self._misses += 1
                return None
            # LRU: move to end
            self._cache.move_to_end(key)
            self._hits += 1
            return entry.message

    def set(self, name: str, qtype: int, qclass: int, message: DNSMessage, ttl: int):
        if ttl <= 0:
            return
        key = self._make_key(name, qtype, qclass)
        with self._lock:
            self._cache[key] = CacheEntry(message, ttl)
            self._cache.move_to_end(key)
            # Evict oldest if over max size
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

    def invalidate(self, name: str):
        """Remove all cache entries for a given name."""
        prefix = name.lower().rstrip(".") + ":"
        with self._lock:
            keys = [k for k in self._cache if k.startswith(prefix)]
            for k in keys:
                del self._cache[k]

    def clear(self):
        with self._lock:
            self._cache.clear()

    def prune(self):
        """Remove all expired entries."""
        with self._lock:
            expired = [k for k, v in self._cache.items() if v.is_expired]
            for k in expired:
                del self._cache[k]

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "size": len(self._cache),
                "max_size": self._max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": (
                    round(self._hits / (self._hits + self._misses) * 100, 1)
                    if (self._hits + self._misses) > 0
                    else 0.0
                ),
            }
