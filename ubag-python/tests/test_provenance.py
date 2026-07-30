import base64
import json
from pathlib import Path

import pytest

from ubag._challenge import MemoryReplayStore
from ubag.provenance import (
    ProvenanceError,
    create_provenance,
    jwk_thumbprint,
    verify_provenance,
)

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "docs/spec/test-vectors/v1.json")
    .read_text(encoding="utf-8")
)
FIXED = VECTORS["fixed"]


def _proof(**overrides):
    values = {
        "method": FIXED["method"],
        "public_origin": FIXED["public_origin"],
        "origin_form": FIXED["origin_form"],
        "body": FIXED["body_utf8"].encode(),
        "jti": FIXED["jti"],
        "issued_at": FIXED["issued_at"],
        "lifetime": FIXED["lifetime"],
    }
    values.update(overrides)
    return create_provenance(FIXED["private_key"], FIXED["public_key"], **values)


def _verify(proof, store=None, **overrides):
    values = {
        "method": FIXED["method"],
        "public_origin": FIXED["public_origin"],
        "origin_form": FIXED["origin_form"],
        "body": FIXED["body_utf8"].encode(),
        "now": FIXED["issued_at"],
        "replay_store": store or MemoryReplayStore(),
    }
    values.update(overrides)
    return verify_provenance(proof, **values)


def _code(proof, **overrides):
    with pytest.raises(ProvenanceError) as exc:
        _verify(proof, **overrides)
    return exc.value.code


def _sign_raw(header_raw: bytes, payload_raw: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    header_part, payload_part = encode(header_raw), encode(payload_raw)
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    private = Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(
        FIXED["private_key"] + "=" * (-len(FIXED["private_key"]) % 4)
    ))
    return f"{header_part}.{payload_part}.{encode(private.sign(signing_input))}"


def test_normative_fixed_vector_and_valid_verification():
    proof = _proof()
    assert proof == FIXED["compact_jws"]
    verified = _verify(proof)
    assert verified.agent_ref.startswith("ubag:sha256:")
    assert verified.credential_ref is None


def test_exact_target_body_method_and_replay_failures():
    proof = _proof()
    assert _code(proof, method="GET") == "METHOD_MISMATCH"
    assert _code(proof, origin_form="/payments?a=1&b=2") == "TARGET_MISMATCH"
    assert _code(proof, body=b'{"amount":11}') == "CONTENT_DIGEST_MISMATCH"
    store = MemoryReplayStore()
    _verify(proof, store=store)
    assert _code(proof, store=store) == "PROVENANCE_REPLAYED"


def test_credential_presence_and_key_binding():
    token = "signed-credential"
    proof = _proof(credential=token, jti="credential-vector")
    claims = {
        "jti": "credential-jti",
        "iss": "https://issuer.example",
        "aud": "https://service.example",
        "cnf": {"jkt": jwk_thumbprint(FIXED["public_key"])},
    }
    verified = _verify(
        proof,
        credential=token,
        credential_validator=lambda value: claims if value == token else None,
    )
    assert verified.credential_ref == "credential-jti"
    assert _code(proof) == "CREDENTIAL_MISMATCH"


def test_wire_identity_resolution_claim_is_rejected():
    proof = _proof()
    header, payload, _ = proof.split(".")
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    decoded["tenant_ref"] = "attacker-tenant"
    # Parsing rejects the forbidden/unknown claim before signature semantics.
    payload = base64.urlsafe_b64encode(
        json.dumps(decoded, separators=(",", ":"), sort_keys=True).encode()
    ).decode().rstrip("=")
    assert _code(f"{header}.{payload}.AA") == "INVALID_CLAIMS"


def test_kid_can_never_substitute_for_verified_key():
    with pytest.raises(ValueError):
        _proof(kid="ubag:sha256:victim")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    valid = _proof()
    header_part, payload_part, _ = valid.split(".")
    header = json.loads(base64.urlsafe_b64decode(
        header_part + "=" * (-len(header_part) % 4)
    ))
    header["kid"] = "ubag:sha256:victim"
    header_part = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    ).decode().rstrip("=")
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    private = Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(
        FIXED["private_key"] + "=" * (-len(FIXED["private_key"]) % 4)
    ))
    signature = base64.urlsafe_b64encode(private.sign(signing_input)).decode().rstrip("=")
    assert _code(f"{header_part}.{payload_part}.{signature}") == "KEY_HINT_MISMATCH"


def test_default_replay_store_is_shared_and_fails_closed():
    value = _proof(jti="python-default-replay-regression")
    kwargs = {
        "method": FIXED["method"],
        "public_origin": FIXED["public_origin"],
        "origin_form": FIXED["origin_form"],
        "body": FIXED["body_utf8"].encode(),
        "now": FIXED["issued_at"],
    }
    verify_provenance(value, **kwargs)
    with pytest.raises(ProvenanceError) as exc:
        verify_provenance(value, **kwargs)
    assert exc.value.code == "PROVENANCE_REPLAYED"


def test_jti_bound_validator_configuration_and_expiry_ttl():
    oversized = _proof(jti="x" * 129)
    assert _code(oversized) == "INVALID_CLAIMS"

    token = "credential-needing-validator"
    credentialed = _proof(credential=token, jti="missing-validator")
    assert _code(credentialed, credential=token) == "VERIFIER_MISCONFIGURED"

    class CaptureStore:
        expires_at = None

        def consume(self, identifier, expires_at):
            self.expires_at = expires_at
            return True

    store = CaptureStore()
    _verify(_proof(jti="ttl-boundary"), store=store)
    assert store.expires_at == FIXED["issued_at"] + FIXED["lifetime"] + 6


def test_noncanonical_duplicate_and_numeric_inputs_have_stable_codes():
    header_part, payload_part, _ = FIXED["compact_jws"].split(".")
    header = base64.urlsafe_b64decode(header_part + "=" * (-len(header_part) % 4))
    payload = base64.urlsafe_b64decode(payload_part + "=" * (-len(payload_part) % 4))

    duplicate_header = header.replace(
        b'{"alg":"EdDSA",', b'{"alg":"EdDSA","alg":"EdDSA",', 1
    )
    assert _code(_sign_raw(duplicate_header, payload)) == "MALFORMED_ENVELOPE"

    decimal_iat = payload.replace(b'"iat":2000000000', b'"iat":2000000000.0', 1)
    assert _code(_sign_raw(header, decimal_iat)) == "MALFORMED_ENVELOPE"

    unsafe = payload.replace(b'"iat":2000000000', b'"iat":9007199254740992', 1)
    assert _code(_sign_raw(header, unsafe)) == "MALFORMED_ENVELOPE"

    tenant_multifault = payload[:-1] + b',"tenant":"attacker"}'
    assert _code(_sign_raw(header, tenant_multifault)) == "MALFORMED_ENVELOPE"

    header_multifault = header[:-1] + b',"aaa":"field"}'
    assert _code(_sign_raw(header_multifault, payload)) == "MALFORMED_ENVELOPE"


def test_replay_capacity_fails_closed_without_losing_prior_entry():
    store = MemoryReplayStore(max_entries=1)
    first = _proof(jti="capacity-victim")
    second = _proof(jti="capacity-flood")
    _verify(first, store=store)
    assert _code(second, store=store) == "REPLAY_STORE_EXHAUSTED"
    assert _code(first, store=store) == "PROVENANCE_REPLAYED"


def test_replay_namespace_quota_contains_one_agent_and_attributes_failure():
    store = MemoryReplayStore(
        max_entries=10,
        max_entries_per_namespace=1,
        namespace_extractor=lambda identifier: identifier.split("|", 1)[0],
    )
    first = _proof(jti="agent-quota-first")
    second = _proof(jti="agent-quota-second")
    _verify(first, store=store)
    with pytest.raises(ProvenanceError) as exc:
        _verify(second, store=store)
    assert exc.value.code == "REPLAY_KEY_QUOTA_EXCEEDED"
    assert exc.value.agent_ref.startswith("ubag:sha256:")

    # The same verified key on another trusted public origin has a separate quota.
    other_origin = "https://other.example"
    other = _proof(
        jti="other-origin",
        public_origin=other_origin,
    )
    verify_provenance(
        other,
        method=FIXED["method"],
        public_origin=other_origin,
        origin_form=FIXED["origin_form"],
        body=FIXED["body_utf8"].encode(),
        replay_store=store,
        now=FIXED["issued_at"],
    )


def test_origin_and_global_exhaustion_never_blame_rejected_agent():
    origin_store = MemoryReplayStore(
        max_entries=10,
        max_entries_per_group=1,
        group_extractor=lambda identifier: identifier.split(":", 1)[0],
    )
    _verify(_proof(jti="origin-first"), store=origin_store)
    with pytest.raises(ProvenanceError) as origin_exc:
        _verify(_proof(jti="origin-second"), store=origin_store)
    assert origin_exc.value.code == "REPLAY_ORIGIN_QUOTA_EXCEEDED"
    assert origin_exc.value.agent_ref is None

    global_store = MemoryReplayStore(max_entries=1)
    _verify(_proof(jti="global-first"), store=global_store)
    with pytest.raises(ProvenanceError) as global_exc:
        _verify(_proof(jti="global-second"), store=global_store)
    assert global_exc.value.code == "REPLAY_STORE_EXHAUSTED"
    assert global_exc.value.agent_ref is None


def test_impure_namespace_extractor_cannot_break_expiry_cleanup(monkeypatch):
    values = iter(("first", "different", "second"))
    store = MemoryReplayStore(
        max_entries=2,
        max_entries_per_namespace=1,
        namespace_extractor=lambda _identifier: next(values),
    )
    monkeypatch.setattr("ubag._challenge.time.time", lambda: 100)
    assert store.consume("one", 101)
    monkeypatch.setattr("ubag._challenge.time.time", lambda: 102)
    assert store.consume("two", 103)
