"""
Asymmetric key primitives for UBAG.

Two key types, each chosen for a reason:

* Agent identity  -> Ed25519. Raw 64-byte signatures, no DER/encoding ambiguity,
  so an agent signature produced in Python verifies byte-for-byte in Node and
  vice-versa. The agent's PUBLIC key is its identity.

* Issuer (credential signing) -> EC P-256 / ES256 JWT. Chosen because it is the
  one asymmetric JWT algorithm supported by BOTH PyJWT and Node's `jsonwebtoken`,
  so a credential minted by either SDK verifies with the other via the issuer's
  PUBLIC key (JWKS) — the OAuth/OIDC model. No shared secret, works across sites.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ── Agent identity keys (Ed25519) ──────────────────────────────────────────────

def generate_agent_keypair() -> tuple[str, str]:
    """Generate an agent identity keypair. Returns (private_b64url, public_b64url)
    of the raw 32-byte Ed25519 keys."""
    sk = ed25519.Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return _b64u(priv), _b64u(pub)


def agent_sign(private_b64: str, message: bytes) -> str:
    """Sign a message with an agent's Ed25519 private key. Returns b64url signature."""
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(_b64u_decode(private_b64))
    return _b64u(sk.sign(message))


def agent_verify(public_b64: str, message: bytes, signature_b64: str) -> bool:
    """Verify an agent's Ed25519 signature over `message`. Never raises."""
    try:
        pk = ed25519.Ed25519PublicKey.from_public_bytes(_b64u_decode(public_b64))
        pk.verify(_b64u_decode(signature_b64), message)
        return True
    except Exception:
        return False


def agent_id(public_b64: str) -> str:
    """Stable agent identity derived from its public key (a key thumbprint).
    This is what `sub` / `cnf` reference — identity is the key, not a claimed name."""
    digest = hashlib.sha256(_b64u_decode(public_b64)).digest()
    return "ubag:" + _b64u(digest)[:43]


# ── Issuer keys (EC P-256, for ES256 credential JWTs) ──────────────────────────

def generate_issuer_keypair() -> tuple[str, str]:
    """Generate an issuer keypair for signing credentials.
    Returns (private_pem, public_pem) for an EC P-256 key (ES256)."""
    sk = ec.generate_private_key(ec.SECP256R1())
    priv = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    pub = sk.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return priv, pub


def issuer_public_from_private(private_pem: str) -> str:
    """Derive the issuer public PEM from its private PEM (so a site configured only
    with the private key can also verify)."""
    sk = serialization.load_pem_private_key(private_pem.encode("ascii"), password=None)
    return sk.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def build_jwks(public_pem: str, kid: str = "ubag-issuer-1") -> dict:
    """Build a JWKS document for the issuer's EC P-256 public key, so resource
    servers can verify credentials by fetching /.well-known/jwks.json."""
    pk = serialization.load_pem_public_key(public_pem.encode("ascii"))
    nums = pk.public_numbers()
    x = nums.x.to_bytes(32, "big")
    y = nums.y.to_bytes(32, "big")
    return {
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "x": _b64u(x),
                "y": _b64u(y),
                "use": "sig",
                "alg": "ES256",
                "kid": kid,
            }
        ]
    }
