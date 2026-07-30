"""
Branch C — agent identity challenge (asymmetric).

An unknown agent is issued a one-time nonce. It proves control of its identity
key by signing the nonce with its Ed25519 PRIVATE key; the server verifies with
the agent's PUBLIC key. That is what establishes *who* the agent is — knowledge
of a shared secret never could.

The nonce carries a server-side HMAC `stamp` so the server can confirm it issued
the nonce without storing it (stateless issuance). That HMAC is the server signing
to *itself* — it is not part of the identity proof.

Replay: nonces are one-time. Provide a shared `store` (Redis/DB) in multi-process
deployments; the in-memory default only protects a single process.
"""
from __future__ import annotations

import hashlib
import heapq
import hmac
import secrets
import threading
import time
from collections import OrderedDict
from typing import Callable, Optional, Protocol

from ubag._keys import agent_id, agent_verify


class UBAGReplayStore(Protocol):
    def consume(self, identifier: str, expires_at: int) -> bool: ...


class ReplayStoreCapacityError(RuntimeError):
    """Replay protection cannot safely retain another live identifier."""

    def __init__(
        self,
        message: str,
        *,
        tier: str = "global",
        namespace: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.tier = tier
        self.namespace = namespace


class MemoryReplayStore:
    """Bounded, thread-safe TTL replay store for one process."""

    def __init__(
        self,
        max_entries: int = 10_000,
        *,
        max_entries_per_namespace: Optional[int] = None,
        namespace_extractor: Optional[Callable[[str], str]] = None,
        max_entries_per_group: Optional[int] = None,
        group_extractor: Optional[Callable[[str], str]] = None,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        if max_entries_per_namespace is not None and max_entries_per_namespace < 1:
            raise ValueError("max_entries_per_namespace must be positive")
        self.max_entries_per_namespace = max_entries_per_namespace
        self._namespace_extractor = namespace_extractor
        if max_entries_per_group is not None and max_entries_per_group < 1:
            raise ValueError("max_entries_per_group must be positive")
        self.max_entries_per_group = max_entries_per_group
        self._group_extractor = group_extractor
        self._entries: OrderedDict[str, int] = OrderedDict()
        self._namespace_counts: dict[str, int] = {}
        self._group_counts: dict[str, int] = {}
        self._expiry_heap: list[tuple[int, str]] = []
        self._lock = threading.Lock()
        self.capacity_exhaustions = 0

    def consume(self, identifier: str, expires_at: int) -> bool:
        now = int(time.time())
        with self._lock:
            while self._expiry_heap and self._expiry_heap[0][0] <= now:
                expiry, key = heapq.heappop(self._expiry_heap)
                if self._entries.get(key) == expiry:
                    self._entries.pop(key, None)
                    namespace = self._namespace(key)
                    if namespace is not None:
                        remaining = max(
                            self._namespace_counts.get(namespace, 0) - 1, 0
                        )
                        if remaining:
                            self._namespace_counts[namespace] = remaining
                        else:
                            self._namespace_counts.pop(namespace, None)
                    group = self._group(key)
                    if group is not None:
                        remaining = max(self._group_counts.get(group, 0) - 1, 0)
                        if remaining:
                            self._group_counts[group] = remaining
                        else:
                            self._group_counts.pop(group, None)
            if identifier in self._entries:
                return False
            namespace = self._namespace(identifier)
            if (
                namespace is not None
                and self.max_entries_per_namespace is not None
                and self._namespace_counts.get(namespace, 0)
                >= self.max_entries_per_namespace
            ):
                self.capacity_exhaustions += 1
                raise ReplayStoreCapacityError(
                    "replay namespace is full of live entries; refusing to fail open",
                    tier="namespace",
                    namespace=namespace,
                )
            group = self._group(identifier)
            if (
                group is not None
                and self.max_entries_per_group is not None
                and self._group_counts.get(group, 0) >= self.max_entries_per_group
            ):
                self.capacity_exhaustions += 1
                raise ReplayStoreCapacityError(
                    "replay group is full of live entries; refusing to fail open",
                    tier="group",
                )
            if len(self._entries) >= self.max_entries:
                self.capacity_exhaustions += 1
                raise ReplayStoreCapacityError(
                    "replay store is full of live entries; refusing to fail open",
                    tier="global",
                )
            self._entries[identifier] = expires_at
            if namespace is not None:
                self._namespace_counts[namespace] = (
                    self._namespace_counts.get(namespace, 0) + 1
                )
            if group is not None:
                self._group_counts[group] = self._group_counts.get(group, 0) + 1
            self._entries.move_to_end(identifier)
            heapq.heappush(self._expiry_heap, (expires_at, identifier))
            # Bounded entries plus a heap gives O(log n) hot-path expiry.
            if len(self._expiry_heap) > (2 * len(self._entries) + 64):
                self._expiry_heap = [
                    (expiry, key) for key, expiry in self._entries.items()
                ]
                heapq.heapify(self._expiry_heap)
            return True

    def _namespace(self, identifier: str) -> Optional[str]:
        if self._namespace_extractor is None:
            return None
        return self._namespace_extractor(identifier)

    def _group(self, identifier: str) -> Optional[str]:
        if self._group_extractor is None:
            return None
        return self._group_extractor(identifier)


class _MemoryNonceStore(MemoryReplayStore):
    """Backward-compatible internal name."""


_default_nonce_store = MemoryReplayStore()
_default_pop_store = MemoryReplayStore()


def _stamp(server_secret: str, nonce: str, ts: int) -> str:
    return hmac.new(
        server_secret.encode(), f"{nonce}:{ts}".encode(), hashlib.sha256
    ).hexdigest()


def generate_challenge(server_secret: str, ttl: int = 120) -> dict:
    """Generate a nonce challenge for an unknown agent (sent in the 429 body).

    The agent must:
      1. read `nonce`
      2. sign the nonce bytes with its Ed25519 private key
      3. POST {nonce, timestamp, stamp, agent_public, signature} to /ubag/verify
    """
    nonce = secrets.token_urlsafe(32)
    ts = int(time.time())
    return {
        "nonce": nonce,
        "timestamp": ts,
        "ttl": ttl,
        "algo": "Ed25519",
        "stamp": _stamp(server_secret, nonce, ts),
        "instructions": (
            "Sign the `nonce` bytes with your Ed25519 private key and POST "
            "{nonce, timestamp, stamp, agent_public, signature} to /ubag/verify."
        ),
    }


def verify_challenge(
    server_secret: str,
    nonce: str,
    timestamp: int,
    stamp: str,
    agent_public: str,
    signature: str,
    ttl: int = 120,
    store: Optional[UBAGReplayStore] = None,
) -> tuple[bool, str, Optional[str]]:
    """Verify a challenge response. Returns (ok, reason, agent_id).

    1. Stamp    — the server issued this exact (nonce, ts), untampered
    2. Expiry   — the timestamp is current and within TTL
    3. Identity — the signature verifies under agent_public
    4. Replay   — the nonce is atomically consumed after verification
    """
    nonce_store = store or _default_nonce_store

    if not nonce or not agent_public or not signature:
        return False, "missing_fields", None

    if not hmac.compare_digest(_stamp(server_secret, nonce, timestamp), stamp):
        return False, "invalid_stamp", None

    now = int(time.time())
    age = now - timestamp
    if age > ttl:
        return False, "nonce_expired", None
    if age < -5:
        return False, "nonce_from_future", None

    # The identity proof: only the holder of the matching private key can produce this.
    if not agent_verify(agent_public, nonce.encode(), signature):
        return False, "bad_signature", None

    try:
        consumed = nonce_store.consume(nonce, timestamp + ttl)
    except ReplayStoreCapacityError:
        return False, "replay_store_exhausted", None
    if not consumed:
        return False, "nonce_already_used", None
    return True, "identity_verified", agent_id(agent_public)


def build_pop_message(
    method: str,
    host: str,
    target: str,
    token: str,
    ts: int,
    jti: str,
) -> bytes:
    """Build the v2 request-bound proof-of-possession message."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return (
        "UBAG-POP-V2\n"
        f"{method.upper()}\n{host.lower()}\n{target}\n{token_hash}\n{int(ts)}\n{jti}"
    ).encode()


def verify_pop(
    agent_public: str,
    method: str,
    host: str,
    target: str,
    token: str,
    ts: int,
    jti: str,
    signature: str,
    max_age: int = 60,
    store: Optional[UBAGReplayStore] = None,
) -> bool:
    """Verify a request-bound, one-time proof of possession.

    The proof covers method, host, path plus query, the credential thumbprint,
    timestamp, and a unique proof identifier. The identifier is atomically
    consumed after signature verification to reject within-window replay.
    """
    if not agent_public or not host or not target or not token or not jti or not signature:
        return False
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        return False
    now = int(time.time())
    if abs(now - ts) > max_age:
        return False
    message = build_pop_message(method, host, target, token, ts, jti)
    if not agent_verify(agent_public, message, signature):
        return False
    replay_store = store or _default_pop_store
    try:
        return replay_store.consume(f"pop:{jti}", now + max_age)
    except ReplayStoreCapacityError:
        return False
