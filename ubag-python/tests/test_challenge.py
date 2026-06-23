"""Tests for Branch C sandbox challenge."""
import hashlib
import hmac
import time

import pytest
from ubag._challenge import generate_challenge, verify_challenge, _MemoryNonceStore

SECRET = "test-secret-32-chars-minimum-ok!"


def _solve(challenge: dict) -> str:
    """Correctly sign a challenge as a legitimate agent would."""
    return hmac.new(
        SECRET.encode(),
        challenge["nonce_id"].encode(),
        hashlib.sha256,
    ).hexdigest()


def test_valid_challenge_accepted():
    store     = _MemoryNonceStore()
    challenge = generate_challenge(SECRET)
    signed    = _solve(challenge)

    ok, reason = verify_challenge(
        secret_key=SECRET,
        nonce_id=challenge["nonce_id"],
        timestamp=challenge["timestamp"],
        mac=challenge["mac"],
        signed_nonce=signed,
        delta_ms=100,
        store=store,
    )
    assert ok is True
    assert reason == "authorized"


def test_replay_rejected():
    store     = _MemoryNonceStore()
    challenge = generate_challenge(SECRET)
    signed    = _solve(challenge)

    verify_challenge(SECRET, challenge["nonce_id"], challenge["timestamp"],
                     challenge["mac"], signed, 100, store=store)

    ok, reason = verify_challenge(SECRET, challenge["nonce_id"], challenge["timestamp"],
                                  challenge["mac"], signed, 100, store=store)
    assert ok is False
    assert reason == "nonce_already_used"


def test_wrong_signature_rejected():
    store     = _MemoryNonceStore()
    challenge = generate_challenge(SECRET)

    ok, reason = verify_challenge(
        secret_key=SECRET,
        nonce_id=challenge["nonce_id"],
        timestamp=challenge["timestamp"],
        mac=challenge["mac"],
        signed_nonce="wrong",
        delta_ms=100,
        store=store,
    )
    assert ok is False
    assert reason == "bad_signature"


def test_cadence_too_fast_rejected():
    store     = _MemoryNonceStore()
    challenge = generate_challenge(SECRET)
    signed    = _solve(challenge)

    ok, reason = verify_challenge(SECRET, challenge["nonce_id"], challenge["timestamp"],
                                  challenge["mac"], signed, delta_ms=1, store=store)
    assert ok is False
    assert reason == "cadence_too_fast"


def test_human_emulated_delay_rejected():
    store     = _MemoryNonceStore()
    challenge = generate_challenge(SECRET)
    signed    = _solve(challenge)

    ok, reason = verify_challenge(SECRET, challenge["nonce_id"], challenge["timestamp"],
                                  challenge["mac"], signed, delta_ms=9999, store=store)
    assert ok is False
    assert reason == "human_emulated_delay"


def test_expired_nonce_rejected():
    import time
    store     = _MemoryNonceStore()
    # Generate challenge with a past timestamp by backdating manually
    nonce_id  = "deadbeef" * 6
    timestamp = int(time.time()) - 9999
    mac       = hmac.new(SECRET.encode(), f"{nonce_id}:{timestamp}".encode(), hashlib.sha256).hexdigest()
    signed    = hmac.new(SECRET.encode(), nonce_id.encode(), hashlib.sha256).hexdigest()

    ok, reason = verify_challenge(
        secret_key=SECRET,
        nonce_id=nonce_id,
        timestamp=timestamp,
        mac=mac,
        signed_nonce=signed,
        delta_ms=100,
        ttl=1,
        store=store,
    )
    assert ok is False
    assert reason == "nonce_expired"
