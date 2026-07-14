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
import hmac
import secrets
import time
from typing import Optional, Protocol

from ubag._keys import agent_id, agent_verify


class UBAGNonceStore(Protocol):
    def exists(self, nonce: str) -> bool: ...
    def mark_used(self, nonce: str) -> None: ...


class _MemoryNonceStore:
    def __init__(self) -> None:
        self._used: set[str] = set()

    def exists(self, nonce: str) -> bool:
        return nonce in self._used

    def mark_used(self, nonce: str) -> None:
        self._used.add(nonce)


_default_store = _MemoryNonceStore()


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
    store: Optional[UBAGNonceStore] = None,
) -> tuple[bool, str, Optional[str]]:
    """Verify a challenge response. Returns (ok, reason, agent_id).

    1. Replay   — nonce not already used
    2. Stamp    — the server issued this exact (nonce, ts), untampered
    3. Expiry   — within TTL
    4. Identity — agent's signature over the nonce verifies under agent_public
    """
    nonce_store = store or _default_store

    if not nonce or not agent_public or not signature:
        return False, "missing_fields", None

    if nonce_store.exists(nonce):
        return False, "nonce_already_used", None

    if not hmac.compare_digest(_stamp(server_secret, nonce, timestamp), stamp):
        return False, "invalid_stamp", None

    if int(time.time()) - timestamp > ttl:
        return False, "nonce_expired", None

    # The identity proof: only the holder of the matching private key can produce this.
    if not agent_verify(agent_public, nonce.encode(), signature):
        return False, "bad_signature", None

    nonce_store.mark_used(nonce)
    return True, "authorized", agent_id(agent_public)


def verify_pop(
    agent_public: str,
    method: str,
    path: str,
    ts: int,
    signature: str,
    max_age: int = 60,
) -> bool:
    """Proof-of-possession for a credentialed request.

    A credential binds to the agent's identity key via its `cnf` claim, but that
    binding is meaningless unless the agent proves, per request, that it still
    holds the key. Here the agent signs the canonical string "METHOD PATH TS"
    with its Ed25519 private key; we verify with the `pub` from the credential's
    `cnf`. This turns the credential from a bearer token (usable by anyone who
    steals it) into a holder-of-key token.

    Returns True only if the timestamp is fresh and the signature verifies.
    """
    if not agent_public or not signature:
        return False
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        return False
    if abs(int(time.time()) - ts) > max_age:
        return False
    message = f"{method.upper()} {path} {ts}".encode()
    return agent_verify(agent_public, message, signature)
