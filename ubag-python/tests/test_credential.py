"""Tests for credential issuance/validation (asymmetric ES256) + agent identity."""
import jwt

from ubag._credential import issue_credential, validate_credential, CREDENTIAL_HEADER
from ubag._challenge import generate_challenge, verify_challenge
from ubag._keys import generate_issuer_keypair, generate_agent_keypair, agent_id
from ubag.agent import AgentCredential


def test_issue_and_validate_roundtrip():
    priv, pub = generate_issuer_keypair()
    token = issue_credential("ubag:agent1", priv)
    claims = validate_credential(token, pub)
    assert claims is not None
    assert claims["sub"] == "ubag:agent1"
    assert claims["agent_class"] == "authorized_agent"
    assert "/*" in claims["paths"]
    assert claims["iss"] == "https://ubagprotocol.com"


def test_wrong_public_key_returns_none():
    priv, _ = generate_issuer_keypair()
    _, other_pub = generate_issuer_keypair()
    token = issue_credential("a", priv)
    assert validate_credential(token, other_pub) is None


def test_expired_token_returns_none():
    priv, pub = generate_issuer_keypair()
    token = jwt.encode({"sub": "a", "iat": 0, "exp": 1}, priv, algorithm="ES256")
    assert validate_credential(token, pub) is None


def test_credential_binds_agent_key():
    ipriv, ipub = generate_issuer_keypair()
    _, apub = generate_agent_keypair()
    token = issue_credential(agent_id(apub), ipriv, agent_public=apub)
    claims = validate_credential(token, ipub)
    assert claims["cnf"]["jkt"] == agent_id(apub)
    assert claims["cnf"]["pub"] == apub


def test_credential_header_name():
    assert CREDENTIAL_HEADER == "X-UBAG-Credential"


def test_agent_identity_is_its_keypair():
    a = AgentCredential.generate(owner="me@example.com")
    assert a.agent_id.startswith("ubag:")
    b = AgentCredential.load(a.export())  # round-trip preserves identity
    assert b.agent_id == a.agent_id


def test_full_handshake_agent_to_credential():
    """Agent solves a site challenge → issuer mints a credential bound to its key →
    the credential validates with the issuer public key."""
    ipriv, ipub = generate_issuer_keypair()
    server_secret = "s"
    agent = AgentCredential.generate()

    ch = generate_challenge(server_secret)
    sol = agent.solve_challenge(ch)
    ok, reason, aid = verify_challenge(
        server_secret, sol["nonce"], sol["timestamp"], sol["stamp"],
        sol["agent_public"], sol["signature"],
    )
    assert ok and aid == agent.agent_id

    token = issue_credential(aid, ipriv, agent_public=agent.public_key)
    agent.set_credential(token)
    headers = agent.headers()
    assert CREDENTIAL_HEADER in headers
    assert validate_credential(headers[CREDENTIAL_HEADER], ipub)["sub"] == agent.agent_id
