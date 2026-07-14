"""
Small bounded TTL cache (LRU eviction).

Used to cache origin HTML fetched for Branch B extraction so the gateway does
not refetch the origin on every agent request. Bounded on BOTH time and size —
a TTL alone leaks memory under crawl traffic, so entries are also LRU-evicted
once the cache is full.
"""
from __future__ import annotations

import time
from collections import OrderedDict
from typing import Any, Optional


class TTLCache:
    def __init__(self, max_size: int = 256, ttl: int = 300) -> None:
        self.max_size = max(1, max_size)
        self.ttl = ttl
        self._store: "OrderedDict[str, tuple[float, Any]]" = OrderedDict()

    def get(self, key: str) -> Optional[Any]:
        item = self._store.get(key)
        if item is None:
            return None
        expiry, value = item
        if time.time() >= expiry:
            self._store.pop(key, None)
            return None
        self._store.move_to_end(key)
        return value

    def set(self, key: str, value: Any) -> None:
        self._store[key] = (time.time() + self.ttl, value)
        self._store.move_to_end(key)
        while len(self._store) > self.max_size:
            self._store.popitem(last=False)  # evict least-recently-used

    def clear(self) -> None:
        self._store.clear()
