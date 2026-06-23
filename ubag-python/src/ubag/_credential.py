"""
JWT credential issuance and validation.

Credentials are short-lived signed JWTs that travel with agent requests.
The secret_key is set once when the middleware is configured.
"""
from __future__ import annotations

import time
from typing import Optional

import jwt

CREDENTIAL_HEADER = "X-UBAG-Credential"
_DEFAULT_TTL      = 300  # 5 minutes


def issue_credential(
    subject: str,
    secret_key: str,
    agent_class: str = "authorized_agent",
    ttl: int = _DEFAULT_TTL,
    allowed_paths: list[str] | None = None,
) -> str:
    now = int(time.time())
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + ttl,
        "agent_class": agent_class,
        "paths": allowed_paths or ["/*"],
    }
    return jwt.encode(payload, secret_key, algorithm="HS256")


def validate_credential(token: str, secret_key: str) -> Optional[dict]:
    """Returns decoded claims if valid, None otherwise."""
    try:
        return jwt.decode(token, secret_key, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
