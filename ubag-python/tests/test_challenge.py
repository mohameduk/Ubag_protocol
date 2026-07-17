"""Tests for Branch C agent identity challenge (asymmetric Ed25519)."""
import time

from ubag._challenge import generate_challenge, verify_challenge, _MemoryNonceStore, _stamp
from ubag._keys import generate_agent_keypair, agent_sign, agent_id

SERVER_SECRET = "server-stamp-secret"


def _solve(challenge: dict, priv: str) -> str:
    return agent_sign(priv, challenge["nonce"].encode())


def test_valid_challenge_accepted():
    store = _MemoryNonceStore()
    priv, pub = generate_agent_keypair()
    ch = generate_challenge(SERVER_SECRET)
    ok, reason, aid = verify_challenge(
        SERVER_SECRET, ch["nonce"], ch["timestamp"], ch["stamp"], pub, _solve(ch, priv), store=store
    )
    assert ok is True
    assert reason == "identity_verified"
    assert aid == agent_id(pub)


def test_replay_rejected():
    store = _MemoryNonceStore()
    priv, pub = generate_agent_keypair()
    ch = generate_challenge(SERVER_SECRET)
    sig = _solve(ch, priv)
    verify_challenge(SERVER_SECRET, ch["nonce"], ch["timestamp"], ch["stamp"], pub, sig, store=store)
    ok, reason, _ = verify_challenge(
        SERVER_SECRET, ch["nonce"], ch["timestamp"], ch["stamp"], pub, sig, store=store
    )
    assert ok is False
    assert reason == "nonce_already_used"


def test_wrong_key_rejected():
    """A signature from a DIFFERENT private key must not validate against pub — the
    whole point of asymmetric identity."""
    store = _MemoryNonceStore()
    _, pub = generate_agent_keypair()
    other_priv, _ = generate_agent_keypair()
    ch = generate_challenge(SERVER_SECRET)
    sig = agent_sign(other_priv, ch["nonce"].encode())
    ok, reason, _ = verify_challenge(
        SERVER_SECRET, ch["nonce"], ch["timestamp"], ch["stamp"], pub, sig, store=store
    )
    assert ok is False
    assert reason == "bad_signature"


def test_tampered_stamp_rejected():
    store = _MemoryNonceStore()
    priv, pub = generate_agent_keypair()
    ch = generate_challenge(SERVER_SECRET)
    ok, reason, _ = verify_challenge(
        SERVER_SECRET, ch["nonce"], ch["timestamp"], "deadbeef", pub, _solve(ch, priv), store=store
    )
    assert ok is False
    assert reason == "invalid_stamp"


def test_expired_nonce_rejected():
    store = _MemoryNonceStore()
    priv, pub = generate_agent_keypair()
    nonce = "x" * 43
    ts = int(time.time()) - 9999
    stamp = _stamp(SERVER_SECRET, nonce, ts)
    sig = agent_sign(priv, nonce.encode())
    ok, reason, _ = verify_challenge(SERVER_SECRET, nonce, ts, stamp, pub, sig, ttl=1, store=store)
    assert ok is False
    assert reason == "nonce_expired"


def test_missing_fields_rejected():
    ok, reason, _ = verify_challenge(SERVER_SECRET, "", 0, "", "", "", store=_MemoryNonceStore())
    assert ok is False
    assert reason == "missing_fields"
