"""A tiny thread-safe, bounded, TTL in-memory cache.

Used for hot paths where recomputation is expensive but the input rarely
changes within a short window:

* verified API-key -> customer (avoids re-running PBKDF2 on every request), and
* decrypted signing material -> plaintext (avoids a KMS/AES decrypt per issuance).

It is intentionally minimal (no background eviction thread): expired entries are
purged lazily on access, and the oldest entry is dropped when the cache is full
(approximate LRU via insertion order). State is per-process; behind multiple
instances each process keeps its own cache, which is fine for these use cases
because entries are self-verifying (API-key path re-checks the stored hash) or
immutable (a given ciphertext always decrypts to the same plaintext).
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Generic, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class TTLCache(Generic[K, V]):
    def __init__(self, *, max_size: int, ttl_seconds: float) -> None:
        self._max_size = max(1, int(max_size))
        self._ttl = float(ttl_seconds)
        self._lock = threading.Lock()
        # key -> (expires_at_monotonic, value)
        self._store: OrderedDict[K, tuple[float, V]] = OrderedDict()

    def get(self, key: K) -> V | None:
        if self._ttl <= 0:
            return None
        now = time.monotonic()
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if expires_at <= now:
                self._store.pop(key, None)
                return None
            # Refresh recency.
            self._store.move_to_end(key)
            return value

    def set(self, key: K, value: V) -> None:
        if self._ttl <= 0:
            return
        expires_at = time.monotonic() + self._ttl
        with self._lock:
            self._store[key] = (expires_at, value)
            self._store.move_to_end(key)
            while len(self._store) > self._max_size:
                self._store.popitem(last=False)

    def invalidate(self, key: K) -> None:
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)
