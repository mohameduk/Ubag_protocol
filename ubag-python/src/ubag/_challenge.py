"""
Branch C — Cryptographic sandbox challenge.

Unknown agents receive a nonce they must sign with HMAC-SHA256.
Agents that solve the challenge can be issued a credential.

Anti-replay: nonces are one-time use. The caller is responsible for
persisting used nonces (pass a `store` dict or implement UBAGNonceStore).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Optional, Protocol


class UBAGNonceStore(Protocol):
    """Minimal interface for nonce persistence. Implement to prevent replay attacks."""
    def exists(self, nonce_id: str) -> bool: ...
    def mark_used(self, nonce_id: str) -> None: ...


# In-memory store — sufficient for single-process deployments
class _MemoryNonceStore:
    def __init__(self) -> None:
        self._used: set[str] = set()

    def exists(self, nonce_id: str) -> bool:
        return nonce_id in self._used

    def mark_used(self, nonce_id: str) -> None:
        self._used.add(nonce_id)


_default_store = _MemoryNonceStore()


def generate_challenge(secret_key: str, client_ip: str = "", ttl: int = 30) -> dict:
    """
    Generate a nonce challenge payload sent in the 429 response.

    The agent must:
      1. Read `nonce_id`
      2. Compute HMAC-SHA256(secret_key, nonce_id) → hex digest
      3. POST to /ubag/verify with the signed value and delta_ms
    """
    nonce_id = secrets.token_hex(24)
    ts       = int(time.time())
    mac      = hmac.new(secret_key.encode(), f"{nonce_id}:{ts}".encode(), hashlib.sha256).hexdigest()
    return {
        "nonce_id":    nonce_id,
        "timestamp":   ts,
        "ttl":         ttl,
        "signing_algo": "HMAC-SHA256",
        "mac":         mac,
        "instructions": (
            "Sign nonce_id with HMAC-SHA256(your_secret, nonce_id) "
            "and POST to /ubag/verify with signed_nonce and delta_ms"
        ),
    }


def verify_challenge(
    secret_key: str,
    nonce_id: str,
    timestamp: int,
    mac: str,
    signed_nonce: str,
    delta_ms: float,
    ttl: int = 30,
    cadence_min_ms: float = 5,
    cadence_max_ms: float = 2000,
    store: Optional[UBAGNonceStore] = None,
) -> tuple[bool, str]:
    """
    Verify a challenge response. Returns (ok, reason).

    Checks:
      1. Replay — nonce not already used
      2. MAC    — nonce payload integrity
      3. Expiry — nonce within TTL
      4. Cadence — delta_ms in [cadence_min_ms, cadence_max_ms]
      5. Signature — agent signed nonce_id correctly
    """
    nonce_store = store or _default_store

    if nonce_store.exists(nonce_id):
        return False, "nonce_already_used"

    expected_mac = hmac.new(
        secret_key.encode(), f"{nonce_id}:{timestamp}".encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_mac, mac):
        return False, "invalid_mac"

    if int(time.time()) - timestamp > ttl:
        return False, "nonce_expired"

    if delta_ms < cadence_min_ms:
        return False, "cadence_too_fast"
    if delta_ms > cadence_max_ms:
        return False, "human_emulated_delay"

    expected_sig = hmac.new(
        secret_key.encode(), nonce_id.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_sig, signed_nonce):
        return False, "bad_signature"

    nonce_store.mark_used(nonce_id)
    return True, "authorized"
