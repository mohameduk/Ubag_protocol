"""Tests for credential issuance and validation."""
import time
import pytest
import jwt

from ubag._credential import issue_credential, validate_credential, CREDENTIAL_HEADER
from ubag.agent import AgentCredential

SECRET = "test-secret-32-chars-minimum-ok!"


def test_issue_and_validate_roundtrip():
    token  = issue_credential("my-agent", SECRET)
    claims = validate_credential(token, SECRET)
    assert claims is not None
    assert claims["sub"] == "my-agent"
    assert claims["agent_class"] == "authorized_agent"
    assert "/*" in claims["paths"]


def test_wrong_secret_returns_none():
    token = issue_credential("agent", SECRET)
    assert validate_credential(token, "wrong-secret") is None


def test_expired_token_returns_none():
    expired = jwt.encode(
        {"sub": "agent", "iat": 0, "exp": 1, "agent_class": "test", "paths": ["/*"]},
        SECRET, algorithm="HS256"
    )
    assert validate_credential(expired, SECRET) is None


def test_credential_header_name():
    assert CREDENTIAL_HEADER == "X-UBAG-Credential"


def test_agent_credential_headers():
    cred    = AgentCredential(subject="bot-v1", secret_key=SECRET)
    headers = cred.headers()
    assert CREDENTIAL_HEADER in headers
    token   = headers[CREDENTIAL_HEADER]
    claims  = validate_credential(token, SECRET)
    assert claims["sub"] == "bot-v1"
    assert claims["agent_class"] == "mcp_agent"


def test_agent_credential_reuses_token():
    cred = AgentCredential(subject="bot-v1", secret_key=SECRET)
    t1   = cred.token()
    t2   = cred.token()
    assert t1 == t2  # same token reused while valid


def test_agent_credential_custom_paths():
    cred    = AgentCredential(subject="bot", secret_key=SECRET, allowed_paths=["/api/*"])
    claims  = validate_credential(cred.token(), SECRET)
    assert "/api/*" in claims["paths"]
