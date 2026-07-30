"""UBAG Provenance Profile 1.0 draft.

The wire object is untrusted until :func:`verify_provenance` returns a
``VerifiedProvenance``. Tenant and principal deliberately do not exist in this
module: they belong to the private resolver.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ubag._challenge import (
    MemoryReplayStore,
    ReplayStoreCapacityError,
    UBAGReplayStore,
)

PROFILE_TYPE = "ubag-provenance+jwt"
MAX_LIFETIME = 60
MAX_CLOCK_SKEW = 5
MAX_JTI_BYTES = 128
MAX_ENVELOPE_BYTES = 65_536
MAX_HEADER_BYTES = 4_096
MAX_PAYLOAD_BYTES = 16_384
MAX_SAFE_INTEGER = 9_007_199_254_740_991
_HEADER_FIELDS = {"typ", "alg", "jwk", "kid"}
_PAYLOAD_FIELDS = {
    "jti", "htm", "htu", "iat", "exp", "ath", "ubag_qsh",
    "ubag_content_digest", "nonce",
}
_FORBIDDEN_FIELDS = {"tenant", "tenant_ref", "principal", "principal_ref"}
# Replay identifiers are "{origin_hash}:{agent_hash}|{jti}". Both hashes are
# unpadded base64url, so neither can contain ":" or "|", while a client-controlled
# jti may contain both. Taking element [0] is what makes that safe, and it is also
# what keeps the two SDKs identical: Python's split(sep, maxsplit) bounds the
# number of splits and JavaScript's split(sep, limit) bounds the number of
# returned elements, so only [0] agrees under both. Do not replace either
# extractor with rsplit or a regex.
_default_provenance_store = MemoryReplayStore(
    max_entries=100_000,
    max_entries_per_namespace=4_096,
    namespace_extractor=lambda identifier: identifier.split("|", 1)[0],
    max_entries_per_group=20_000,
    group_extractor=lambda identifier: identifier.split(":", 1)[0],
)


class ProvenanceError(ValueError):
    def __init__(
        self,
        code: str,
        message: str = "",
        *,
        agent_ref: Optional[str] = None,
    ) -> None:
        super().__init__(message or code)
        self.code = code
        self.agent_ref = agent_ref


@dataclass(frozen=True)
class ProvenanceEnvelope:
    compact_jws: str
    header: dict
    payload: dict
    payload_bytes: bytes
    signing_input: bytes
    signature: bytes


@dataclass(frozen=True)
class VerifiedProvenance:
    agent_ref: str
    public_key: str
    credential_ref: Optional[str]
    issuer: Optional[str]
    audience: Optional[object]
    method: str
    htu: str
    origin_form: str
    content_digest: str
    jti: str
    issued_at: int
    expires_at: int
    nonce: Optional[str] = None


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("invalid base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _strict_json(data: bytes) -> dict:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    def bad_constant(value):
        raise ValueError(f"non-I-JSON number: {value}")

    value = json.loads(
        data.decode("utf-8", errors="strict"),
        object_pairs_hook=pairs,
        parse_constant=bad_constant,
    )
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


def _jcs(value: dict) -> bytes:
    # Profile claims contain strings, integers, and flat JSON objects only; this
    # is RFC 8785 canonical form for that deliberately bounded value domain.
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _validate_json_number_domain(value) -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, float):
        raise ProvenanceError("MALFORMED_ENVELOPE",
                              "floating-point claims are outside the profile")
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ProvenanceError("MALFORMED_ENVELOPE",
                                  "integer exceeds interoperable safe range")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_number_domain(item)
        return
    if isinstance(value, dict):
        for item in value.values():
            _validate_json_number_domain(item)
        return
    raise ProvenanceError("MALFORMED_ENVELOPE")


def parse_provenance(compact_jws: str) -> ProvenanceEnvelope:
    try:
        if not isinstance(compact_jws, str):
            raise ValueError
        if len(compact_jws.encode("utf-8")) > MAX_ENVELOPE_BYTES:
            raise ValueError("envelope too large")
        parts = compact_jws.split(".")
        if len(parts) != 3 or not all(parts):
            raise ValueError
        header_raw, payload_raw, signature_raw = map(_b64u_decode, parts)
        if len(header_raw) > MAX_HEADER_BYTES or len(payload_raw) > MAX_PAYLOAD_BYTES:
            raise ValueError("JWS component too large")
        header = _strict_json(header_raw)
        payload = _strict_json(payload_raw)
        _validate_json_number_domain(header)
        _validate_json_number_domain(payload)
        if header_raw != _jcs(header):
            raise ValueError("protected header is not RFC 8785 canonical JSON")
        if payload_raw != _jcs(payload):
            raise ValueError("payload is not RFC 8785 canonical JSON")
        signature = signature_raw
        if set(header) - _HEADER_FIELDS or "crit" in header:
            raise ProvenanceError("UNSUPPORTED_PROFILE", "unsupported protected header")
        if set(payload) & _FORBIDDEN_FIELDS:
            raise ProvenanceError("INVALID_CLAIMS", "identity resolution claim on wire")
        if set(payload) - _PAYLOAD_FIELDS:
            raise ProvenanceError("INVALID_CLAIMS", "unknown payload claim")
        return ProvenanceEnvelope(
            compact_jws=compact_jws,
            header=header,
            payload=payload,
            payload_bytes=payload_raw,
            signing_input=f"{parts[0]}.{parts[1]}".encode("ascii"),
            signature=signature,
        )
    except ProvenanceError:
        raise
    except Exception as exc:
        raise ProvenanceError("MALFORMED_ENVELOPE") from exc


def content_digest(body: bytes) -> str:
    """RFC 9530 sha-256 dictionary member for the exact content bytes."""
    if not isinstance(body, bytes):
        raise TypeError("body must be bytes")
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    return f"sha-256=:{digest}:"


def query_string_hash(origin_form: str) -> str:
    """Hash exact origin-form UTF-8 bytes without parsing or normalization."""
    if not isinstance(origin_form, str) or not origin_form.startswith("/"):
        raise ValueError("origin_form must begin with '/'")
    if "#" in origin_form:
        raise ValueError("origin_form must not contain a fragment")
    return _b64u(hashlib.sha256(origin_form.encode("utf-8")).digest())


def jwk_thumbprint(public_b64: str) -> str:
    canonical = (
        '{"crv":"Ed25519","kty":"OKP","x":' + json.dumps(public_b64, separators=(",", ":")) + "}"
    ).encode("utf-8")
    return _b64u(hashlib.sha256(canonical).digest())


def agent_ref(public_b64: str) -> str:
    return "ubag:sha256:" + _b64u(hashlib.sha256(_b64u_decode(public_b64)).digest())


def credential_hash(token: str) -> str:
    return _b64u(hashlib.sha256(token.encode("utf-8")).digest())


def _public_key(header: dict) -> tuple[str, Ed25519PublicKey]:
    if header.get("typ") != PROFILE_TYPE or header.get("alg") != "EdDSA":
        raise ProvenanceError("UNSUPPORTED_PROFILE")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or set(jwk) != {"kty", "crv", "x"}:
        raise ProvenanceError("UNSUPPORTED_PROFILE", "exact Ed25519 public JWK required")
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ProvenanceError("UNSUPPORTED_PROFILE")
    try:
        public_raw = _b64u_decode(jwk["x"])
        if len(public_raw) != 32:
            raise ValueError
        return jwk["x"], Ed25519PublicKey.from_public_bytes(public_raw)
    except Exception as exc:
        raise ProvenanceError("UNSUPPORTED_PROFILE", "invalid Ed25519 JWK") from exc


def verify_provenance(
    compact_jws: str,
    *,
    method: str,
    public_origin: str,
    origin_form: str,
    body: bytes = b"",
    credential: Optional[str] = None,
    credential_validator: Optional[Callable[[str], Optional[dict]]] = None,
    replay_store: Optional[UBAGReplayStore] = None,
    expected_nonce: Optional[str] = None,
    now: Optional[int] = None,
) -> VerifiedProvenance:
    envelope = parse_provenance(compact_jws)
    public_b64, key = _public_key(envelope.header)
    try:
        key.verify(envelope.signature, envelope.signing_input)
    except Exception as exc:
        raise ProvenanceError("INVALID_SIGNATURE") from exc
    derived_agent_ref = agent_ref(public_b64)
    if "kid" in envelope.header and envelope.header["kid"] != derived_agent_ref:
        raise ProvenanceError("KEY_HINT_MISMATCH")

    p = envelope.payload
    required = {"jti", "htm", "htu", "iat", "exp", "ubag_qsh", "ubag_content_digest"}
    if not required.issubset(p):
        raise ProvenanceError("INVALID_CLAIMS", "required claim missing")
    if not all(isinstance(p.get(name), str) and p[name] for name in
               ("jti", "htm", "htu", "ubag_qsh", "ubag_content_digest")):
        raise ProvenanceError("INVALID_CLAIMS")
    if len(p["jti"].encode("utf-8")) > MAX_JTI_BYTES:
        raise ProvenanceError("INVALID_CLAIMS", "jti exceeds 128 bytes")
    if isinstance(p.get("iat"), bool) or isinstance(p.get("exp"), bool):
        raise ProvenanceError("INVALID_CLAIMS")
    if not isinstance(p.get("iat"), int) or not isinstance(p.get("exp"), int):
        raise ProvenanceError("INVALID_CLAIMS")
    if p["exp"] <= p["iat"] or p["exp"] - p["iat"] > MAX_LIFETIME:
        raise ProvenanceError("INVALID_CLAIMS", "invalid proof lifetime")
    current = int(time.time()) if now is None else int(now)
    if p["iat"] > current + MAX_CLOCK_SKEW or p["exp"] < current - MAX_CLOCK_SKEW:
        raise ProvenanceError("PROOF_EXPIRED")

    expected_method = method.upper()
    if p["htm"] != expected_method:
        raise ProvenanceError("METHOD_MISMATCH")
    path = origin_form.split("?", 1)[0]
    expected_htu = public_origin.rstrip("/") + path
    if p["htu"] != expected_htu:
        raise ProvenanceError("ORIGIN_MISMATCH")
    if p["ubag_qsh"] != query_string_hash(origin_form):
        raise ProvenanceError("TARGET_MISMATCH")
    expected_digest = content_digest(body)
    if p["ubag_content_digest"] != expected_digest:
        raise ProvenanceError("CONTENT_DIGEST_MISMATCH")

    claims = None
    if credential is None:
        if "ath" in p:
            raise ProvenanceError("CREDENTIAL_MISMATCH")
    else:
        if credential_validator is None:
            raise ProvenanceError("VERIFIER_MISCONFIGURED",
                                  "credential validator is required")
        if p.get("ath") != credential_hash(credential):
            raise ProvenanceError("CREDENTIAL_MISMATCH")
        claims = credential_validator(credential)
        if not isinstance(claims, dict):
            raise ProvenanceError("CREDENTIAL_MISMATCH")
        cnf = claims.get("cnf")
        if not isinstance(cnf, dict) or cnf.get("jkt") != jwk_thumbprint(public_b64):
            raise ProvenanceError("CREDENTIAL_MISMATCH")

    supplied_nonce = p.get("nonce")
    if expected_nonce is not None:
        if supplied_nonce != expected_nonce:
            raise ProvenanceError("NONCE_MISMATCH")
    elif supplied_nonce is not None:
        raise ProvenanceError("NONCE_MISMATCH", "unsolicited nonce")

    store = replay_store if replay_store is not None else _default_provenance_store
    origin_namespace = _b64u(hashlib.sha256(
        public_origin.rstrip("/").encode("utf-8")
    ).digest())
    agent_namespace = _b64u(hashlib.sha256(
        derived_agent_ref.encode("utf-8")
    ).digest())
    try:
        consumed = store.consume(
            f"{origin_namespace}:{agent_namespace}|{p['jti']}",
            p["exp"] + MAX_CLOCK_SKEW + 1,
        )
    except ReplayStoreCapacityError as exc:
        if exc.tier == "namespace":
            raise ProvenanceError(
                "REPLAY_KEY_QUOTA_EXCEEDED",
                agent_ref=derived_agent_ref,
            ) from exc
        if exc.tier == "group":
            raise ProvenanceError("REPLAY_ORIGIN_QUOTA_EXCEEDED") from exc
        raise ProvenanceError("REPLAY_STORE_EXHAUSTED") from exc
    if not consumed:
        raise ProvenanceError("PROVENANCE_REPLAYED")

    return VerifiedProvenance(
        agent_ref=derived_agent_ref,
        public_key=public_b64,
        credential_ref=claims.get("jti") if claims else None,
        issuer=claims.get("iss") if claims else None,
        audience=claims.get("aud") if claims else None,
        method=expected_method,
        htu=expected_htu,
        origin_form=origin_form,
        content_digest=expected_digest,
        jti=p["jti"],
        issued_at=p["iat"],
        expires_at=p["exp"],
        nonce=supplied_nonce,
    )


def create_provenance(
    private_b64: str,
    public_b64: str,
    *,
    method: str,
    public_origin: str,
    origin_form: str,
    body: bytes = b"",
    credential: Optional[str] = None,
    jti: str,
    issued_at: Optional[int] = None,
    lifetime: int = MAX_LIFETIME,
    nonce: Optional[str] = None,
    kid: Optional[str] = None,
) -> str:
    if not 1 <= lifetime <= MAX_LIFETIME:
        raise ValueError("lifetime must be between 1 and 60 seconds")
    issued = int(time.time()) if issued_at is None else int(issued_at)
    path = origin_form.split("?", 1)[0]
    header = {
        "typ": PROFILE_TYPE,
        "alg": "EdDSA",
        "jwk": {"kty": "OKP", "crv": "Ed25519", "x": public_b64},
    }
    if kid:
        if kid != agent_ref(public_b64):
            raise ValueError("kid must equal the reference derived from public_b64")
        header["kid"] = kid
    payload = {
        "jti": jti,
        "htm": method.upper(),
        "htu": public_origin.rstrip("/") + path,
        "iat": issued,
        "exp": issued + lifetime,
        "ubag_qsh": query_string_hash(origin_form),
        "ubag_content_digest": content_digest(body),
    }
    if credential is not None:
        payload["ath"] = credential_hash(credential)
    if nonce is not None:
        payload["nonce"] = nonce
    encoded_header = _b64u(_jcs(header))
    encoded_payload = _b64u(_jcs(payload))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    private = Ed25519PrivateKey.from_private_bytes(_b64u_decode(private_b64))
    return f"{encoded_header}.{encoded_payload}.{_b64u(private.sign(signing_input))}"
