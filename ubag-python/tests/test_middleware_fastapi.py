"""Integration tests for the FastAPI middleware — three branches (asymmetric)."""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ubag import UBAGMiddleware
from ubag._credential import CREDENTIAL_HEADER, issue_credential
from ubag._keys import generate_issuer_keypair, generate_agent_keypair, agent_sign

ISSUER_PRIV, ISSUER_PUB = generate_issuer_keypair()


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


def test_branch_b_with_valid_credential():
    token = issue_credential("ubag:test-agent", ISSUER_PRIV)
    r = client.get("/hello", headers={CREDENTIAL_HEADER: token})
    assert r.status_code == 200
    assert r.headers["x-ubag-branch"] == "B-AGENT"
    body = r.json()
    assert body["ubag:branch"] == "B-AGENT"
    assert body["ubag:agent"] == "ubag:test-agent"


def test_branch_b_returns_jsonld_content_type():
    token = issue_credential("ubag:test-agent", ISSUER_PRIV)
    r = client.get("/hello", headers={CREDENTIAL_HEADER: token})
    assert "application/ld+json" in r.headers["content-type"]


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
    # the credential it just issued must work for Branch B
    r2 = client.get("/hello", headers={CREDENTIAL_HEADER: cred})
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
