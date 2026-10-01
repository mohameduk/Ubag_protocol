"""Web Bot Auth, tested for the things that make a verifier worth having.

A verifier that only ever checks signatures it produced itself is worthless, so
most of what follows is adversarial: tampered authorities, a stolen passport
pointed at an attacker's key directory, a directory that lies about which key is
which, an expiry window wide enough to be permanent.

The last group is the one that matters commercially. Verification returns an
identity and nothing else. If these tests ever start asserting that a verified
agent is allowed to do something, the layer has collapsed into the thing
Cloudflare already ships for free.

    python -m pytest tests/test_webbotauth.py -q
"""
from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ubag.webbotauth import (TAG, DirectoryFetcher, WebBotAuthError,
                             build_directory, directory_url, jwk_thumbprint,
                             public_jwk, sign_request, signature_base,
                             verify_web_bot_auth)

AGENT = "https://bot.example.com"
URL = "https://gym.example.org/api/bookings"


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def directory(key) -> dict:
    return build_directory([key])


def signed(key, method="POST", url=URL, agent=AGENT, **kw) -> dict:
    return sign_request(key, method, url, agent, **kw)


def verify(headers, directory, method="POST", url=URL, **kw):
    return verify_web_bot_auth(method, url, headers, directory, **kw)


# ---------------------------------------------------------------------------
# It works at all
# ---------------------------------------------------------------------------

def test_a_signed_request_verifies(key, directory):
    agent = verify(signed(key), directory)
    assert agent.issuer == AGENT
    assert agent.keyid == jwk_thumbprint(public_jwk(key)["x"])
    assert agent.nonce and agent.created and agent.expires


def test_the_signature_base_has_no_trailing_newline():
    """The single most common reason one of these never verifies anything."""
    base = signature_base(["@authority"], '("@authority");created=1',
                          "GET", "https://x.test/", {})
    assert base == b'"@authority": x.test\n"@signature-params": ("@authority");created=1'
    assert not base.endswith(b"\n")


def test_the_default_port_is_absent_and_a_custom_one_is_not():
    assert b'"@authority": x.test\n' in signature_base(
        ["@authority"], "()", "GET", "https://x.test:443/", {})
    assert b'"@authority": x.test:8443\n' in signature_base(
        ["@authority"], "()", "GET", "https://x.test:8443/", {})


# ---------------------------------------------------------------------------
# Tampering
# ---------------------------------------------------------------------------

def test_a_signature_for_one_host_does_not_verify_at_another(key, directory):
    """@authority is the required component precisely so a passport presented to
    one site cannot be replayed at a different one."""
    headers = signed(key, url="https://gym.example.org/x")
    with pytest.raises(WebBotAuthError) as exc:
        verify(headers, directory, url="https://other.example.net/x")
    assert exc.value.reason == "BAD_SIGNATURE"


def test_swapping_the_signature_agent_breaks_the_signature(key, directory):
    """The attack this defends against: an intermediary rewrites Signature-Agent
    to a directory it controls, so the request verifies against its own key.

    Covering the header is what stops it, so the rewrite has to break the
    signature rather than redirect the key lookup.
    """
    headers = signed(key)
    headers["Signature-Agent"] = '"https://attacker.example.net"'
    with pytest.raises(WebBotAuthError) as exc:
        verify(headers, directory)
    assert exc.value.reason == "BAD_SIGNATURE"


def test_an_unsigned_signature_agent_is_refused(key, directory):
    """Sending the header but leaving it out of the covered components would make
    the swap above free."""
    headers = sign_request(key, "POST", URL, AGENT, extra_components=())
    headers["Signature-Input"] = headers["Signature-Input"].replace(
        '("@authority" "signature-agent")', '("@authority")')
    with pytest.raises(WebBotAuthError) as exc:
        verify(headers, directory)
    assert exc.value.reason == "AGENT_NOT_COVERED"


def test_a_truncated_signature_is_not_treated_as_a_short_key(key, directory):
    headers = signed(key)
    headers["Signature"] = headers["Signature"][:20] + ":"
    with pytest.raises(WebBotAuthError) as exc:
        verify(headers, directory)
    assert exc.value.reason == "BAD_SIGNATURE"


# ---------------------------------------------------------------------------
# Time, which is the difference between a passport and a permanent key
# ---------------------------------------------------------------------------

def test_an_expired_signature_is_refused(key, directory):
    """Re-signed rather than edited in place.

    Editing the header instead would change the signature base, so the request
    would be refused as BAD_SIGNATURE and this test would pass while proving
    nothing at all about the clock.
    """
    old = int(time.time()) - 10_000
    headers = _resign_with_params(key, [("created", old),
                                        ("expires", old + 300),
                                        ("keyid", _keyid(key)),
                                        ("alg", "ed25519"),
                                        ("nonce", _nonce()),
                                        ("tag", TAG)])
    with pytest.raises(WebBotAuthError) as exc:
        verify(headers, directory)
    assert exc.value.reason == "EXPIRED"


def test_a_signature_with_no_expiry_is_refused_by_default(key, directory):
    """An unexpiring signature is a bearer token someone can keep forever. The
    draft only RECOMMENDS an expiry; for an authorization gateway that is not
    enough, so it is required here and the caller has to opt out deliberately.
    """
    headers = _resign_with_params(key, [("created", int(time.time())),
                                        ("keyid", _keyid(key)),
                                        ("alg", "ed25519"),
                                        ("nonce", _nonce()),
                                        ("tag", TAG)])
    with pytest.raises(WebBotAuthError) as exc:
        verify(headers, directory)
    assert exc.value.reason == "MISSING_EXPIRES"
    assert verify(headers, directory, require_expires=False).issuer == AGENT


def test_a_window_wider_than_a_day_is_refused(key, directory):
    now = int(time.time())
    headers = _resign_with_params(key, [("created", now),
                                        ("expires", now + 400_000),
                                        ("keyid", _keyid(key)),
                                        ("alg", "ed25519"),
                                        ("nonce", _nonce()),
                                        ("tag", TAG)])
    with pytest.raises(WebBotAuthError) as exc:
        verify(headers, directory)
    assert exc.value.reason == "WINDOW_TOO_LONG"


def test_a_signature_created_in_the_future_is_refused(key, directory):
    now = int(time.time()) + 100_000
    headers = _resign_with_params(key, [("created", now),
                                        ("expires", now + 300),
                                        ("keyid", _keyid(key)),
                                        ("alg", "ed25519"),
                                        ("nonce", _nonce()),
                                        ("tag", TAG)])
    with pytest.raises(WebBotAuthError) as exc:
        verify(headers, directory)
    assert exc.value.reason == "NOT_YET_VALID"


# ---------------------------------------------------------------------------
# Key lookup, which is self-verifying or it is nothing
# ---------------------------------------------------------------------------

def test_a_key_absent_from_the_directory_is_unknown(key):
    with pytest.raises(WebBotAuthError) as exc:
        verify(signed(key), build_directory([Ed25519PrivateKey.generate()]))
    assert exc.value.reason == "UNKNOWN_KEY"


def test_a_directory_cannot_relabel_someone_elses_key(key):
    """keyid is the RFC 7638 thumbprint, so the lookup proves itself.

    A directory that lists an unrelated key under the thumbprint it wants is
    caught without any signature check, because the name is derived from the key
    material rather than asserted beside it.
    """
    impostor = build_directory([Ed25519PrivateKey.generate()])
    impostor["keys"][0]["kid"] = _keyid(key)
    with pytest.raises(WebBotAuthError) as exc:
        verify(signed(key), impostor)
    assert exc.value.reason == "UNKNOWN_KEY"

    # And when a caller opts into kid matching, the signature still has to hold.
    with pytest.raises(WebBotAuthError) as exc:
        verify(signed(key), impostor, allow_kid_match=True)
    assert exc.value.reason == "BAD_SIGNATURE"


def test_an_expired_key_in_the_directory_is_refused(key):
    directory = build_directory([key])
    directory["keys"][0]["exp"] = int(time.time()) - 10_000
    with pytest.raises(WebBotAuthError) as exc:
        verify(signed(key), directory)
    assert exc.value.reason == "KEY_EXPIRED"


# ---------------------------------------------------------------------------
# The URL we are told to fetch, which is chosen by the stranger
# ---------------------------------------------------------------------------

def test_only_the_well_known_path_is_ever_fetched():
    """Signature-Agent is attacker-controlled input to an outbound request.

    Honouring a path from it would turn every verifier into a request-forgery
    proxy for whoever signed, so the path is derived rather than accepted.
    """
    assert directory_url(AGENT).endswith(
        "/.well-known/http-message-signatures-directory")
    assert directory_url(AGENT + "/.well-known/http-message-signatures-directory")
    for bad in (f"{AGENT}/internal/admin", f"{AGENT}/?x=1", f"{AGENT}/#f"):
        with pytest.raises(WebBotAuthError):
            directory_url(bad)


def test_plaintext_agent_urls_are_refused():
    with pytest.raises(WebBotAuthError) as exc:
        directory_url("http://bot.example.com")
    assert exc.value.reason == "INSECURE_AGENT_URL"


def test_the_fetcher_refuses_a_host_outside_its_allowlist():
    """No network: the allowlist is checked before anything is resolved."""
    fetcher = DirectoryFetcher(allow=["signature-agent.test"])
    with pytest.raises(WebBotAuthError) as exc:
        fetcher("https://bot.example.com")
    assert exc.value.reason == "AGENT_NOT_ALLOWED"


@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "10.0.0.1"])
def test_the_fetcher_refuses_an_address_that_is_not_publicly_routable(host):
    """169.254.169.254 is the cloud metadata endpoint, which is the whole reason
    this check exists: on Cloud Run, a stranger naming it in a header would
    otherwise have the verifier fetch service credentials on their behalf."""
    with pytest.raises(WebBotAuthError) as exc:
        DirectoryFetcher()(f"https://{host}")
    assert exc.value.reason == "PRIVATE_ADDRESS"


# ---------------------------------------------------------------------------
# Profile rules
# ---------------------------------------------------------------------------

def test_an_untagged_signature_is_not_a_web_bot_auth_signature(key, directory):
    """Other RFC 9421 signatures travel on the same headers. Reaching for one of
    those and calling the result a verified agent would be a confused deputy."""
    headers = signed(key)
    headers["Signature-Input"] = headers["Signature-Input"].replace(
        f';tag="{TAG}"', '')
    with pytest.raises(WebBotAuthError) as exc:
        verify(headers, directory)
    assert exc.value.reason == "NO_WEB_BOT_AUTH_SIGNATURE"


def test_a_non_ed25519_alg_is_refused(key, directory):
    headers = signed(key)
    headers["Signature-Input"] = headers["Signature-Input"].replace(
        'alg="ed25519"', 'alg="rsa-pss-sha512"')
    with pytest.raises(WebBotAuthError) as exc:
        verify(headers, directory)
    assert exc.value.reason == "UNSUPPORTED_ALG"


def test_a_nonce_without_entropy_is_refused(key, directory):
    now = int(time.time())
    headers = _resign_with_params(key, [("created", now),
                                        ("expires", now + 300),
                                        ("keyid", _keyid(key)),
                                        ("alg", "ed25519"),
                                        ("nonce", "aaaa"),
                                        ("tag", TAG)])
    with pytest.raises(WebBotAuthError) as exc:
        verify(headers, directory)
    assert exc.value.reason == "BAD_NONCE"


def test_a_component_we_cannot_rebuild_is_refused_not_guessed(key, directory):
    headers = signed(key)
    headers["Signature-Input"] = headers["Signature-Input"].replace(
        '"@authority"', '"@query-param";name="q" "@authority"')
    with pytest.raises(WebBotAuthError) as exc:
        verify(headers, directory)
    assert exc.value.reason == "UNSUPPORTED_COMPONENT"


def test_the_right_signature_is_found_among_several(key, directory):
    """A request can carry an unrelated signature alongside the passport."""
    headers = signed(key)
    headers["Signature-Input"] = (
        'other=("@method");created=1;keyid="x", ' + headers["Signature-Input"])
    headers["Signature"] = "other=:AAAA:, " + headers["Signature"]
    assert verify(headers, directory).label == "sig1"


def test_whitespace_in_the_received_header_still_verifies(key, directory):
    """Signers serialize differently and a verifier that only accepts its own
    byte-for-byte output will reject real traffic. Both the received bytes and a
    canonical re-serialization are tried."""
    headers = signed(key)
    headers["Signature-Input"] = headers["Signature-Input"].replace(
        '("@authority" "signature-agent")', '( "@authority"  "signature-agent" )')
    assert verify(headers, directory).issuer == AGENT


def test_a_noncanonical_signer_verifies_on_the_received_bytes(key, directory):
    """The mirror image: someone signed over spacing we would not have produced.

    Their bytes are the bytes they hashed, so the received form is tried first.
    """
    params = '( "@authority" "signature-agent" );created={};expires={};keyid="{}";alg="ed25519";nonce="{}";tag="{}"'.format(
        int(time.time()), int(time.time()) + 300, _keyid(key), _nonce(), TAG)
    headers = {"Signature-Agent": f'"{AGENT}"'}
    base = signature_base(["@authority", "signature-agent"], params,
                          "POST", URL, headers)
    from ubag.provenance import _b64u
    headers["Signature-Input"] = f"sig1={params}"
    headers["Signature"] = f"sig1=:{_b64u(key.sign(base))}:"
    assert verify(headers, directory).issuer == AGENT


def test_an_unsigned_request_says_so(directory):
    with pytest.raises(WebBotAuthError) as exc:
        verify({"User-Agent": "GPTBot/1.0"}, directory)
    assert exc.value.reason == "NOT_SIGNED"


# ---------------------------------------------------------------------------
# What a verified passport is NOT
# ---------------------------------------------------------------------------

def test_verification_returns_identity_and_no_permissions(key, directory):
    """The commercial boundary, as an assertion.

    Cloudflare's programme answers who is asking. If this result ever grows a
    field saying what the agent may do, UBAG has stopped selling the half nobody
    else sells and started competing with a free product.
    """
    agent = verify(signed(key), directory)
    fields = set(vars(agent))
    for forbidden in ("allowed", "verbs", "tier", "decision", "permissions", "scope"):
        assert forbidden not in fields


def test_a_verified_agent_reads_as_one_more_issuer(key, directory):
    """It lands in the same ``iss`` field a UBAG credential lands in, so a site's
    existing tier table can name it without a second code path."""
    claims = verify(signed(key), directory).as_claims()
    assert claims["iss"] == AGENT == claims["sub"]
    assert claims["agent_class"] == "web_bot_auth_agent"
    assert "paths" not in claims and "verbs" not in claims


def test_a_pinned_directory_with_no_agent_url_still_names_the_issuer(key, directory):
    """A site may pin the keys and skip the header entirely. The identity is then
    the key, so it is spelled as one rather than left blank: an empty issuer is a
    single typo in a policy table away from matching every unidentified caller.
    """
    from ubag.provenance import _b64u
    from ubag.webbotauth import _serialize_params
    now = int(time.time())
    params = [("created", now), ("expires", now + 300), ("keyid", _keyid(key)),
              ("alg", "ed25519"), ("nonce", _nonce()), ("tag", TAG)]
    serialized = _serialize_params(["@authority"], params)
    base = signature_base(["@authority"], serialized, "POST", URL, {})
    headers = {"Signature-Input": f"sig1={serialized}",
               "Signature": f"sig1=:{_b64u(key.sign(base))}:"}
    assert verify(headers, directory).issuer == f"urn:ubag:keyid:{_keyid(key)}"


def test_without_a_pinned_directory_an_agent_url_is_required(key):
    """There is nowhere to fetch keys from, so this is a refusal, not a guess.

    Signed for real: a stub signature would be rejected on length first and this
    would pass without ever reaching the check it names.
    """
    from ubag.provenance import _b64u
    from ubag.webbotauth import _serialize_params
    now = int(time.time())
    serialized = _serialize_params(["@authority"], [
        ("created", now), ("expires", now + 300), ("keyid", _keyid(key)),
        ("alg", "ed25519"), ("nonce", _nonce()), ("tag", TAG)])
    base = signature_base(["@authority"], serialized, "POST", URL, {})
    headers = {"Signature-Input": f"sig1={serialized}",
               "Signature": f"sig1=:{_b64u(key.sign(base))}:"}
    with pytest.raises(WebBotAuthError) as exc:
        verify_web_bot_auth("POST", URL, headers,
                            lambda _url: pytest.fail("fetched without an agent URL"))
    assert exc.value.reason == "NO_AGENT_URL"


def test_nothing_in_verification_touches_the_network(key, directory, monkeypatch):
    """Passing a directory in must mean exactly that. A verifier that quietly
    fetches is a verifier that can be made to hang on a stranger's slow server.
    """
    import socket as socket_module
    monkeypatch.setattr(socket_module, "getaddrinfo",
                        lambda *a, **k: pytest.fail("resolved a hostname"))
    assert verify(signed(key), directory).issuer == AGENT


# ---------------------------------------------------------------------------
# The spec's own vectors, which is the only evidence that counts
# ---------------------------------------------------------------------------
#
# Everything above verifies signatures this module produced, which proves only
# that it is self-consistent. These two are from Appendix A.2 of
# draft-meunier-web-bot-auth-architecture-02, signed with the Ed25519 key in
# Appendix B.1.4 of RFC 9421, by someone else's implementation. Copied verbatim
# with the RFC 8792 line wrapping undone.
#
# Note what they do that our own signer does not: parameters in the order
# created, keyid, alg, expires, nonce, tag, and nonces in standard base64 with
# "/" and "=" in them. Both were places this could have been written to accept
# only its own output and looked correct doing it.

VECTOR_JWK_X = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
VECTOR_KEYID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
VECTOR_DIRECTORY = {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": VECTOR_JWK_X}]}
VECTOR_URL = "https://example.com/path/to/resource"
VECTOR_NOW = 1735689700.0  # inside created=1735689600 .. expires=1735693200

_V1_NONCE = ("mYotfW3CUjI68sbGw6oKd7kyXqPjZEtU8xFPGWFrqOAf5qC6MDe3pys3SWWCudB0"
             "MvwslHy32WXUpkR7u0lt/w==")
_V2_NONCE = ("e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT"
             "9RUKAJ0qVkU0mEeLElW1qg==")

VECTOR_A21 = {
    "Signature-Input": (
        'sig1=("@authority");created=1735689600'
        f';keyid="{VECTOR_KEYID}";alg="ed25519";expires=1735693200'
        f';nonce="{_V1_NONCE}";tag="web-bot-auth"'),
    "Signature": (
        "sig1=:+NA/cssf4Y2bQTMTkyvTGRCaVzp9quyUevdwwMtMOWhhOOZ2T1subBj0Btvdnrp"
        "DEuwSAbiTeElXDzHL3WWKCw==:"),
}

VECTOR_A22 = {
    "Signature-Agent": '"https://signature-agent.test"',
    "Signature-Input": (
        'sig2=("@authority" "signature-agent");created=1735689600'
        f';keyid="{VECTOR_KEYID}";alg="ed25519";expires=1735693200'
        f';nonce="{_V2_NONCE}";tag="web-bot-auth"'),
    "Signature": (
        "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZ"
        "Dsi6nJKuHxUi/5Syp3rLWBA==:"),
}


@pytest.fixture
def at_vector_time(monkeypatch):
    """The vectors are dated 1 January 2025 and would otherwise read as expired."""
    monkeypatch.setattr(time, "time", lambda: VECTOR_NOW)
    import ubag.webbotauth as module
    monkeypatch.setattr(module.time, "time", lambda: VECTOR_NOW)


def test_the_published_keyid_is_the_thumbprint_of_the_published_key():
    """Confirms the thumbprint against a value the spec computed independently."""
    assert jwk_thumbprint(VECTOR_JWK_X) == VECTOR_KEYID


def test_spec_vector_a21_without_a_signature_agent(at_vector_time):
    agent = verify_web_bot_auth("GET", VECTOR_URL, dict(VECTOR_A21), VECTOR_DIRECTORY)
    assert agent.keyid == VECTOR_KEYID
    assert agent.created == 1735689600 and agent.expires == 1735693200
    assert agent.issuer == f"urn:ubag:keyid:{VECTOR_KEYID}"


def test_spec_vector_a22_with_a_signature_agent(at_vector_time):
    agent = verify_web_bot_auth("GET", VECTOR_URL, dict(VECTOR_A22), VECTOR_DIRECTORY)
    assert agent.issuer == "https://signature-agent.test"
    assert agent.components == ("@authority", "signature-agent")


def test_the_spec_vectors_are_refused_at_todays_clock():
    """Not pedantry: these are real, published, valid-forever-if-you-let-them
    signatures. An implementation that accepts them outside their window accepts
    a replay of a two-year-old request."""
    for vector in (VECTOR_A21, VECTOR_A22):
        with pytest.raises(WebBotAuthError) as exc:
            verify_web_bot_auth("GET", VECTOR_URL, dict(vector), VECTOR_DIRECTORY)
        assert exc.value.reason == "EXPIRED"


def test_a_spec_vector_does_not_verify_at_a_different_authority(at_vector_time):
    with pytest.raises(WebBotAuthError) as exc:
        verify_web_bot_auth("GET", "https://evil.example.net/path/to/resource",
                            dict(VECTOR_A22), VECTOR_DIRECTORY)
    assert exc.value.reason == "BAD_SIGNATURE"


# ---------------------------------------------------------------------------
# Helpers: re-sign with parameters sign_request would never emit
# ---------------------------------------------------------------------------

def _keyid(key) -> str:
    return jwk_thumbprint(public_jwk(key)["x"])


def _nonce() -> str:
    import os

    from ubag.provenance import _b64u
    return _b64u(os.urandom(64))


def _resign_with_params(key, params) -> dict:
    from ubag.provenance import _b64u
    from ubag.webbotauth import _serialize_params
    components = ["@authority", "signature-agent"]
    headers = {"Signature-Agent": f'"{AGENT}"'}
    serialized = _serialize_params(components, params)
    base = signature_base(components, serialized, "POST", URL, headers)
    headers["Signature-Input"] = f"sig1={serialized}"
    headers["Signature"] = f"sig1=:{_b64u(key.sign(base))}:"
    return headers
