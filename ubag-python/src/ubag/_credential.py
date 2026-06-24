"""
Credential issuance and validation (asymmetric, ES256).

A credential is a short-lived JWT signed by the ISSUER's private key and verified
with the issuer's PUBLIC key. Because verification needs only the public key
(distributable via JWKS), any independent site can validate a credential without
holding any secret — the OAuth/OIDC model.

The credential is bound to the agent's identity key via the `cnf` (confirmation)
claim, so a verifier can later require proof-of-possession of the agent key.
"""
from __future__ import annotations

import time
from typing import Optional

import jwt

from ubag._keys import agent_id

CREDENTIAL_HEADER = "X-UBAG-Credential"
_DEFAULT_TTL = 300  # 5 minutes
_ALG = "ES256"


def issue_credential(
    subject: str,
    issuer_private_pem: str,
    agent_public: Optional[str] = None,
    agent_class: str = "authorized_agent",
    ttl: int = _DEFAULT_TTL,
    allowed_paths: list[str] | None = None,
    issuer: str = "https://ubagprotocol.com",
    kid: str = "ubag-issuer-1",
) -> str:
    """Mint a credential JWT signed with the issuer's EC P-256 private key (ES256)."""
    now = int(time.time())
    payload = {
        "iss": issuer,
        "sub": subject,
        "iat": now,
        "exp": now + ttl,
        "agent_class": agent_class,
        "paths": allowed_paths or ["/*"],
    }
    if agent_public:
        # Bind the credential to the agent's identity key (key thumbprint).
        payload["cnf"] = {"jkt": agent_id(agent_public), "pub": agent_public}
    return jwt.encode(payload, issuer_private_pem, algorithm=_ALG, headers={"kid": kid})


def validate_credential(token: str, issuer_public_pem: str) -> Optional[dict]:
    """Return decoded claims if the credential is validly signed by the issuer,
    else None. Verifies with the issuer's PUBLIC key — no shared secret."""
    try:
        return jwt.decode(token, issuer_public_pem, algorithms=[_ALG])
    except jwt.PyJWTError:
        return None
