"""Integration tests for the FastAPI middleware — all three branches."""
import hashlib
import hmac

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ubag import UBAGMiddleware
from ubag._credential import CREDENTIAL_HEADER, issue_credential

SECRET = "test-secret-32-chars-minimum-ok!"


def make_app(**kwargs) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        UBAGMiddleware,
        secret_key=SECRET,
        site_meta={"name": "Test Store", "type": "Store"},
        **kwargs,
    )

    @app.get("/hello")
    def hello():
        return {"msg": "from origin app"}

    return app


client = TestClient(make_app(), raise_server_exceptions=True)


# ------------------------------------------------------------------
# agents.json
# ------------------------------------------------------------------

def test_agents_json_served():
    r = client.get("/agents.json")
    assert r.status_code == 200
    body = r.json()
    assert body["ubag_version"] == "1.0"
    assert "B-AGENT" in body["branches"]
    assert "C-SANDBOX" in body["branches"]


# ------------------------------------------------------------------
# Branch B — credentialed agent
# ------------------------------------------------------------------

def test_branch_b_with_valid_credential():
    token = issue_credential("test-agent", SECRET)
    r     = client.get("/hello", headers={CREDENTIAL_HEADER: token})
    assert r.status_code == 200
    assert r.headers["x-ubag-branch"] == "B-AGENT"
    body = r.json()
    assert body["@context"] == "https://schema.org"
    assert body["ubag:branch"] == "B-AGENT"
    assert body["ubag:agent"] == "test-agent"


def test_branch_b_returns_jsonld_content_type():
    token = issue_credential("test-agent", SECRET)
    r     = client.get("/hello", headers={CREDENTIAL_HEADER: token})
    assert "application/ld+json" in r.headers["content-type"]


# ------------------------------------------------------------------
# Branch C — unknown bot
# ------------------------------------------------------------------

def test_branch_c_machine_ua_gets_challenge():
    r = client.get("/hello", headers={"user-agent": "python-requests/2.31", "accept": "*/*"})
    assert r.status_code == 429
    assert r.headers["x-ubag-branch"] == "C-SANDBOX"
    body = r.json()
    assert body["status"] == "challenge_required"
    assert "nonce_id" in body["ubag_challenge"]


def test_branch_c_gptbot_gets_challenge():
    r = client.get("/hello", headers={"user-agent": "GPTBot/1.0", "accept": "*/*"})
    assert r.status_code == 429


# ------------------------------------------------------------------
# Branch A — human browser (no origin configured → falls through to app)
# ------------------------------------------------------------------

def test_branch_a_human_reaches_app():
    r = client.get(
        "/hello",
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120",
            "accept": "text/html,application/xhtml+xml,*/*",
        },
    )
    assert r.status_code == 200
    assert r.json() == {"msg": "from origin app"}


# ------------------------------------------------------------------
# /ubag/verify — challenge solve flow
# ------------------------------------------------------------------

def test_verify_valid_challenge():
    # Step 1: get a challenge
    r1   = client.get("/hello", headers={"user-agent": "curl/8.5", "accept": "*/*"})
    ch   = r1.json()["ubag_challenge"]

    # Step 2: solve it correctly
    signed = hmac.new(SECRET.encode(), ch["nonce_id"].encode(), hashlib.sha256).hexdigest()
    r2 = client.post("/ubag/verify", json={
        "nonce_id":    ch["nonce_id"],
        "timestamp":   ch["timestamp"],
        "mac":         ch["mac"],
        "signed_nonce": signed,
        "delta_ms":    100,
        "agent_id":    "my-bot-v1",
    })
    assert r2.status_code == 200
    body = r2.json()
    assert body["status"] == "authorized"
    assert "credential" in body


def test_verify_replay_rejected():
    r1  = client.get("/hello", headers={"user-agent": "curl/8.5", "accept": "*/*"})
    ch  = r1.json()["ubag_challenge"]
    signed = hmac.new(SECRET.encode(), ch["nonce_id"].encode(), hashlib.sha256).hexdigest()

    payload = {"nonce_id": ch["nonce_id"], "timestamp": ch["timestamp"],
               "mac": ch["mac"], "signed_nonce": signed, "delta_ms": 100}

    client.post("/ubag/verify", json=payload)  # first use — OK
    r2 = client.post("/ubag/verify", json=payload)  # replay — must fail
    assert r2.status_code == 403
    assert r2.json()["reason"] == "nonce_already_used"


def test_verify_wrong_signature_rejected():
    r1  = client.get("/hello", headers={"user-agent": "curl/8.5", "accept": "*/*"})
    ch  = r1.json()["ubag_challenge"]

    r2 = client.post("/ubag/verify", json={
        "nonce_id":    ch["nonce_id"],
        "timestamp":   ch["timestamp"],
        "mac":         ch["mac"],
        "signed_nonce": "bad-signature",
        "delta_ms":    100,
    })
    assert r2.status_code == 403
