"""
Credential issuance and validation (asymmetric, ES256).

A credential is a short-lived JWT signed by the ISSUER's private key and verified
with the issuer's PUBLIC key. A receiving site must explicitly trust that key and
validate the configured issuer and audience; JWKS availability alone does not
establish trust.

The credential is bound to the agent's identity key via the `cnf` (confirmation)
claim, so a verifier can later require proof-of-possession of the agent key.
"""
from __future__ import annotations

import time
import uuid
from fnmatch import fnmatchcase
from typing import Optional

import jwt

from ubag._keys import agent_id

CREDENTIAL_HEADER = "X-UBAG-Credential"
_DEFAULT_TTL = 300  # 5 minutes
_ALG = "ES256"
DEFAULT_ISSUER = "https://ubagprotocol.com"
DEFAULT_AUDIENCE = "ubag-web"


def issue_credential(
    subject: str,
    issuer_private_pem: str,
    agent_public: Optional[str] = None,
    agent_class: str = "self_asserted_agent",
    ttl: int = _DEFAULT_TTL,
    allowed_paths: list[str] | None = None,
    issuer: str = DEFAULT_ISSUER,
    audience: str = DEFAULT_AUDIENCE,
    kid: str = "ubag-issuer-1",
) -> str:
    """Mint a credential JWT signed with the issuer's EC P-256 private key (ES256)."""
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "iat": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
        "agent_class": agent_class,
        "paths": allowed_paths or ["/*"],
    }
    if agent_public:
        # Bind the credential to the agent's identity key (key thumbprint).
        payload["cnf"] = {"jkt": agent_id(agent_public), "pub": agent_public}
    return jwt.encode(payload, issuer_private_pem, algorithm=_ALG, headers={"kid": kid})


def validate_credential(
    token: str,
    issuer_public_pem: str,
    issuer: str = DEFAULT_ISSUER,
    audience: str = DEFAULT_AUDIENCE,
) -> Optional[dict]:
    """Return decoded claims if the credential is validly signed by the issuer,
    else None. Verifies with the issuer's PUBLIC key — no shared secret."""
    try:
        return jwt.decode(
            token,
            issuer_public_pem,
            algorithms=[_ALG],
            issuer=issuer,
            audience=audience,
            options={"require": ["iss", "aud", "sub", "iat", "exp", "jti"]},
        )
    except jwt.PyJWTError:
        return None


def credential_path_allowed(claims: dict, path: str) -> bool:
    """Return whether a credential's path grants include the requested path."""
    grants = claims.get("paths")
    if not isinstance(grants, list) or not grants:
        return False
    return any(isinstance(pattern, str) and fnmatchcase(path, pattern) for pattern in grants)
