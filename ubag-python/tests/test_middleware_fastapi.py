"""Integration tests for the FastAPI middleware — three branches (asymmetric)."""
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from ubag import UBAGMiddleware
from ubag._credential import CREDENTIAL_HEADER, issue_credential
from ubag._keys import generate_issuer_keypair, generate_agent_keypair, agent_sign

ISSUER_PRIV, ISSUER_PUB = generate_issuer_keypair()


def pop_headers(cred: str, apriv: str, method: str = "GET", path: str = "/hello") -> dict:
    """Build credential + proof-of-possession headers for a request."""
    ts = int(time.time())
    msg = f"{method.upper()} {path} {ts}".encode()
    return {
        CREDENTIAL_HEADER: cred,
        "X-UBAG-PoP": agent_sign(apriv, msg),
        "X-UBAG-PoP-TS": str(ts),
    }


def make_app(**kwargs) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        UBAGMiddleware,
        issuer_key=ISSUER_PRIV,
        site_meta={"name": "Test Store", "type": "Store"},
        **kwargs,
    )

    @app.get("/hello")
    def hello():
        return {"msg": "from origin app"}

    return app


client = TestClient(make_app(), raise_server_exceptions=True)


def test_ubag_json_served():
    r = client.get("/.well-known/ubag.json")
    assert r.status_code == 200
    assert r.json()["ubag_version"] == "1.0"
    assert r.json()["discovery"]["ubag_json"].endswith("/.well-known/ubag.json")


def test_agents_json_legacy_alias_still_served():
    r = client.get("/agents.json")
    assert r.status_code == 200
    assert r.json()["ubag_version"] == "1.0"


def test_branch_b_with_valid_credential_and_pop():
    apriv, apub = generate_agent_keypair()
    token = issue_credential("ubag:test-agent", ISSUER_PRIV, agent_public=apub)
    r = client.get("/hello", headers=pop_headers(token, apriv))
    assert r.status_code == 200
    assert r.headers["x-ubag-branch"] == "B-AGENT"
    body = r.json()
    assert body["ubag:branch"] == "B-AGENT"
    assert body["ubag:agent"] == "ubag:test-agent"


def test_branch_b_returns_jsonld_content_type():
    apriv, apub = generate_agent_keypair()
    token = issue_credential("ubag:test-agent", ISSUER_PRIV, agent_public=apub)
    r = client.get("/hello", headers=pop_headers(token, apriv))
    assert "application/ld+json" in r.headers["content-type"]


# ── Proof-of-possession security regression tests ──────────────────────────────

def test_stolen_credential_without_pop_is_rejected():
    """A valid credential presented as a bare bearer token (no PoP) must fail closed."""
    _, apub = generate_agent_keypair()
    token = issue_credential("ubag:victim", ISSUER_PRIV, agent_public=apub)
    r = client.get("/hello", headers={CREDENTIAL_HEADER: token})
    assert r.status_code == 401
    assert r.json()["status"] == "pop_required"


def test_stolen_credential_with_attacker_key_is_rejected():
    """Even signing PoP with a different key than the credential binds to must fail."""
    _, victim_pub = generate_agent_keypair()
    attacker_priv, _ = generate_agent_keypair()
    token = issue_credential("ubag:victim", ISSUER_PRIV, agent_public=victim_pub)
    r = client.get("/hello", headers=pop_headers(token, attacker_priv))
    assert r.status_code == 401


def test_stale_pop_timestamp_is_rejected():
    """A replayed PoP older than max_age must fail."""
    apriv, apub = generate_agent_keypair()
    token = issue_credential("ubag:test-agent", ISSUER_PRIV, agent_public=apub)
    old_ts = int(time.time()) - 3600
    msg = f"GET /hello {old_ts}".encode()
    r = client.get("/hello", headers={
        CREDENTIAL_HEADER: token,
        "X-UBAG-PoP": agent_sign(apriv, msg),
        "X-UBAG-PoP-TS": str(old_ts),
    })
    assert r.status_code == 401


def test_require_pop_false_allows_legacy_bearer():
    """Back-compat: with require_pop=False a bare credential still reaches Branch B."""
    legacy = TestClient(make_app(require_pop=False))
    token = issue_credential("ubag:legacy", ISSUER_PRIV)
    r = legacy.get("/hello", headers={CREDENTIAL_HEADER: token})
    assert r.status_code == 200
    assert r.headers["x-ubag-branch"] == "B-AGENT"


def test_missing_secret_and_issuer_refuses_to_start():
    """No server_secret and no issuer_key must raise, not fall back to a known key."""
    import pytest
    app = FastAPI()
    with pytest.raises(ValueError):
        app.add_middleware(UBAGMiddleware, issuer_public_key="")
        TestClient(app).get("/")


def test_branch_c_machine_ua_gets_challenge():
    r = client.get("/hello", headers={"user-agent": "python-requests/2.31", "accept": "*/*"})
    assert r.status_code == 429
    assert r.headers["x-ubag-branch"] == "C-SANDBOX"
    body = r.json()
    assert body["status"] == "challenge_required"
    assert "nonce" in body["ubag_challenge"]
    assert body["ubag_challenge"]["algo"] == "Ed25519"


def test_branch_a_human_reaches_app():
    r = client.get(
        "/hello",
        headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120",
                 "accept": "text/html,application/xhtml+xml,*/*"},
    )
    assert r.status_code == 200
    assert r.json() == {"msg": "from origin app"}


def test_verify_full_flow_issues_working_credential():
    apriv, apub = generate_agent_keypair()
    ch = client.get("/hello", headers={"user-agent": "curl/8.5", "accept": "*/*"}).json()["ubag_challenge"]
    r = client.post("/ubag/verify", json={
        "nonce": ch["nonce"], "timestamp": ch["timestamp"], "stamp": ch["stamp"],
        "agent_public": apub, "signature": agent_sign(apriv, ch["nonce"].encode()),
    })
    assert r.status_code == 200
    cred = r.json()["credential"]
    # the credential it just issued must work for Branch B (with proof-of-possession)
    r2 = client.get("/hello", headers=pop_headers(cred, apriv))
    assert r2.headers["x-ubag-branch"] == "B-AGENT"


def test_verify_wrong_key_rejected():
    apriv, apub = generate_agent_keypair()
    other_priv, _ = generate_agent_keypair()
    ch = client.get("/hello", headers={"user-agent": "curl/8.5", "accept": "*/*"}).json()["ubag_challenge"]
    r = client.post("/ubag/verify", json={
        "nonce": ch["nonce"], "timestamp": ch["timestamp"], "stamp": ch["stamp"],
        "agent_public": apub, "signature": agent_sign(other_priv, ch["nonce"].encode()),
    })
    assert r.status_code == 403
    assert r.json()["reason"] == "bad_signature"


def test_verify_replay_rejected():
    apriv, apub = generate_agent_keypair()
    ch = client.get("/hello", headers={"user-agent": "curl/8.5", "accept": "*/*"}).json()["ubag_challenge"]
    payload = {
        "nonce": ch["nonce"], "timestamp": ch["timestamp"], "stamp": ch["stamp"],
        "agent_public": apub, "signature": agent_sign(apriv, ch["nonce"].encode()),
    }
    client.post("/ubag/verify", json=payload)
    r = client.post("/ubag/verify", json=payload)
    assert r.status_code == 403
    assert r.json()["reason"] == "nonce_already_used"
