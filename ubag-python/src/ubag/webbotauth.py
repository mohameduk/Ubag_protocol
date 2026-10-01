"""
Web Bot Auth: verifying someone else's passport.

An agent signs its request with an Ed25519 key and names the directory where its
public key lives. We fetch the directory, match the key by thumbprint, and check
the signature. What comes back is an identity, a URL, and nothing more.

That boundary is the whole point. Cloudflare's Verified AI Agent programme, and
the draft behind it, answer "who is asking". They do not answer "may this one do
this, to this, now". So a verified passport is not an allow decision here: it is
one more trusted issuer, landing in the same ``issuer`` field a UBAG credential
lands in, to be weighed by whatever policy the site already has. An agent with a
flawless signature still cannot cancel a booking it does not own.

Wire format is draft-meunier-web-bot-auth-architecture over RFC 9421:

    Signature-Agent: "https://bot.example.com"
    Signature-Input: sig1=("@authority" "signature-agent");created=...;expires=...
                     ;keyid="<RFC 7638 thumbprint>";alg="ed25519";nonce="..."
                     ;tag="web-bot-auth"
    Signature: sig1=:<base64 Ed25519>:

Two things here are deliberately awkward.

``verify_web_bot_auth`` does no network I/O. It takes the directory, or something
that can produce one. Fetching is a separate, explicit object, because the URL
being fetched is chosen by the party we are trying to authenticate: a server-side
request forgery primitive by construction, not by accident. ``DirectoryFetcher``
is where that risk is contained, and where an allowlist belongs.

Replay is not solved here and does not pretend to be. The nonce comes back on the
result; a verifier that cares has to remember it. ``ubag._challenge`` already has
the store for that.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,
                                                               Ed25519PublicKey)

from ubag.provenance import _b64u, _b64u_decode, jwk_thumbprint

SIGNATURE_AGENT_HEADER = "Signature-Agent"
SIGNATURE_INPUT_HEADER = "Signature-Input"
SIGNATURE_HEADER = "Signature"
DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
DIRECTORY_CONTENT_TYPE = "application/http-message-signatures-directory+json"

TAG = "web-bot-auth"
ALG = "ed25519"
REQUIRED_COMPONENTS = ("@authority",)
MAX_AGE = 86_400          # the draft's RECOMMENDED ceiling on expires - created
CLOCK_SKEW = 300          # tolerance for a signer whose clock runs fast
NONCE_MIN_BYTES = 16      # the draft RECOMMENDS 64; below 16 is not a nonce

# Derived components we can rebuild from (method, url). Anything outside this set
# makes the signature base unreconstructable, and a base we had to guess at is
# worse than a refusal.
_DERIVED = ("@authority", "@method", "@target-uri", "@path", "@query", "@scheme")


class WebBotAuthError(Exception):
    """Verification failed. ``reason`` is a stable code; ``detail`` is for humans."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class VerifiedAgent:
    """A proven claim about who sent a request, and nothing about what they may do.

    ``issuer`` is the Signature-Agent URL, named to match the field the rest of
    UBAG keys trust on, so a Cloudflare-signed agent is just another issuer in a
    site's tier table rather than a parallel code path. When no Signature-Agent
    was sent and the verifier was handed a pinned directory, it is instead
    ``urn:ubag:keyid:<thumbprint>`` -- never empty.
    """

    issuer: str
    keyid: str
    nonce: Optional[str]
    created: Optional[int]
    expires: Optional[int]
    label: str
    components: tuple[str, ...]

    @property
    def agent_class(self) -> str:
        return "web_bot_auth_agent"

    def as_claims(self) -> dict:
        """Shape it like a validated credential so existing policy can read it."""
        return {
            "iss": self.issuer,
            "sub": self.issuer,
            "agent_class": self.agent_class,
            "iat": self.created,
            "exp": self.expires,
            "jti": self.nonce,
            "keyid": self.keyid,
        }


# ---------------------------------------------------------------------------
# Structured fields, parsed only as far as this profile needs
# ---------------------------------------------------------------------------

def _split_top_level(raw: str, sep: str) -> list[str]:
    """Split on ``sep`` while ignoring separators inside quotes or parentheses."""
    out: list[str] = []
    buf: list[str] = []
    depth, quoted, escaped = 0, False, False
    for ch in raw:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if quoted:
            buf.append(ch)
            if ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
            continue
        if ch == '"':
            quoted = True
            buf.append(ch)
        elif ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth -= 1
            buf.append(ch)
        elif ch == sep and depth == 0:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if quoted or depth:
        raise WebBotAuthError("MALFORMED_HEADER", "unbalanced quotes or parentheses")
    out.append("".join(buf))
    return out


def _unquote(raw: str) -> str:
    if len(raw) < 2 or not raw.startswith('"') or not raw.endswith('"'):
        raise WebBotAuthError("MALFORMED_HEADER", f"expected a quoted string: {raw!r}")
    out: list[str] = []
    escaped = False
    for ch in raw[1:-1]:
        if escaped:
            if ch not in ('"', "\\"):
                raise WebBotAuthError("MALFORMED_HEADER", "bad string escape")
            out.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            raise WebBotAuthError("MALFORMED_HEADER", "unescaped quote in string")
        else:
            out.append(ch)
    if escaped:
        raise WebBotAuthError("MALFORMED_HEADER", "trailing escape in string")
    return "".join(out)


def _b64_any(value: str) -> bytes:
    """Decode either base64 alphabet.

    RFC 8941 byte sequences are standard base64, and the draft's own test vectors
    carry nonces full of ``/`` and ``+``, while this package speaks url-safe
    everywhere else. Accepting both is not politeness; a verifier that only read
    one alphabet would reject the spec's published examples.
    """
    normalised = value.strip().replace("+", "-").replace("/", "_").rstrip("=")
    return _b64u_decode(normalised)


def _bare_item(raw: str) -> Any:
    raw = raw.strip()
    if raw.startswith('"'):
        return _unquote(raw)
    if len(raw) >= 2 and raw.startswith(":") and raw.endswith(":"):
        try:
            return _b64_any(raw[1:-1])
        except Exception as exc:
            raise WebBotAuthError("MALFORMED_HEADER", "bad byte sequence") from exc
    if raw in ("?0", "?1"):
        return raw == "?1"
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    if not raw:
        raise WebBotAuthError("MALFORMED_HEADER", "empty item")
    return raw  # a token, e.g. an unquoted alg some signer emitted


def _parse_params(raw: str) -> list[tuple[str, Any]]:
    """Parameters in the order received, because order decides the signature base."""
    params: list[tuple[str, Any]] = []
    for part in _split_top_level(raw, ";"):
        part = part.strip()
        if not part:
            continue
        name, sep, value = part.partition("=")
        name = name.strip()
        if not name:
            raise WebBotAuthError("MALFORMED_HEADER", "parameter with no name")
        params.append((name, _bare_item(value) if sep else True))
    return params


def _parse_dictionary(raw: str) -> list[tuple[str, str]]:
    """Dictionary members as ``(label, raw value)``, value kept verbatim.

    Verbatim matters: the ``@signature-params`` line of the signature base is the
    serialized value of this member, and the bytes the signer actually hashed are
    the bytes they sent. Re-serializing first and hoping it matches is how these
    verifiers end up rejecting valid signatures.
    """
    members: list[tuple[str, str]] = []
    for member in _split_top_level(raw, ","):
        member = member.strip()
        if not member:
            continue
        label, sep, value = member.partition("=")
        if not sep:
            raise WebBotAuthError("MALFORMED_HEADER", f"dictionary member {member!r}")
        members.append((label.strip(), value.strip()))
    return members


def parse_signature_input(
    raw: str,
) -> dict[str, tuple[tuple[str, ...], list[tuple[str, Any]], str]]:
    """``label -> (covered components, params in order, raw serialized value)``."""
    parsed: dict[str, tuple[tuple[str, ...], list[tuple[str, Any]], str]] = {}
    for label, value in _parse_dictionary(raw):
        if not value.startswith("("):
            raise WebBotAuthError("MALFORMED_HEADER",
                                  "covered components must be an inner list")
        if ")" not in value:
            raise WebBotAuthError("MALFORMED_HEADER", "unterminated inner list")
        close = value.index(")")
        inner, rest = value[1:close], value[close + 1:]
        components: list[str] = []
        for item in _split_top_level(inner, " "):
            item = item.strip()
            if not item:
                continue
            if ";" in item:
                # "@query-param";name="q" and friends. We cannot rebuild those
                # from (method, url) alone, so we refuse rather than guess.
                raise WebBotAuthError("UNSUPPORTED_COMPONENT", item)
            components.append(_unquote(item).lower())
        if rest and not rest.startswith(";"):
            raise WebBotAuthError("MALFORMED_HEADER", f"trailing junk {rest!r}")
        params = _parse_params(rest[1:]) if rest.startswith(";") else []
        parsed[label] = (tuple(components), params, value)
    return parsed


def _serialize_params(components: Iterable[str],
                      params: list[tuple[str, Any]]) -> str:
    inner = " ".join(f'"{c}"' for c in components)
    out = [f"({inner})"]
    for name, value in params:
        if value is True:
            out.append(f";{name}")
        elif value is False:
            out.append(f";{name}=?0")
        elif isinstance(value, int):
            out.append(f";{name}={value}")
        elif isinstance(value, str):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            out.append(f';{name}="{escaped}"')
        else:
            out.append(f";{name}={value}")
    return "".join(out)


# ---------------------------------------------------------------------------
# The signature base (RFC 9421 section 2.5)
# ---------------------------------------------------------------------------

def _authority(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host:
        raise WebBotAuthError("BAD_REQUEST", "no authority in URL")
    port = parts.port
    default = {"http": 80, "https": 443}.get(parts.scheme.lower())
    return f"{host}:{port}" if port and port != default else host


def _field_value(headers: dict, name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name:
            if isinstance(value, (list, tuple)):
                return ", ".join(str(v).strip() for v in value)
            return str(value).strip()
    raise WebBotAuthError("MISSING_COVERED_FIELD", name)


def _derived_value(name: str, method: str, url: str) -> str:
    parts = urlsplit(url)
    if name == "@authority":
        return _authority(url)
    if name == "@method":
        return method.upper()
    if name == "@target-uri":
        return url
    if name == "@path":
        return parts.path or "/"
    if name == "@query":
        return f"?{parts.query}" if parts.query else "?"
    if name == "@scheme":
        return parts.scheme.lower()
    raise WebBotAuthError("UNSUPPORTED_COMPONENT", name)


def signature_base(
    components: Iterable[str],
    signature_params: str,
    method: str,
    url: str,
    headers: dict,
) -> bytes:
    """Build the exact bytes that were signed.

    No trailing newline after the ``@signature-params`` line: that one byte is the
    most common reason an otherwise-correct implementation of this never verifies
    anything.
    """
    lines = []
    for name in components:
        value = (_derived_value(name, method, url) if name.startswith("@")
                 else _field_value(headers, name))
        lines.append(f'"{name}": {value}')
    lines.append(f'"@signature-params": {signature_params}')
    return "\n".join(lines).encode("utf-8")


# ---------------------------------------------------------------------------
# Key directories
# ---------------------------------------------------------------------------

def directory_url(signature_agent: str) -> str:
    """Where the signer's keys live, derived without trusting a supplied path.

    The header may name the origin or the directory itself. Either way the only
    path we will ever fetch is the well-known one, so a signer cannot point the
    verifier at an arbitrary URL on its own host and have it fetched.
    """
    parts = urlsplit(signature_agent)
    if parts.scheme != "https":
        raise WebBotAuthError("INSECURE_AGENT_URL",
                              f"https required, got {parts.scheme!r}")
    if not parts.hostname:
        raise WebBotAuthError("BAD_AGENT_URL", signature_agent)
    if parts.query or parts.fragment:
        raise WebBotAuthError("BAD_AGENT_URL", "query and fragment are not allowed")
    if parts.path not in ("", "/", DIRECTORY_PATH):
        raise WebBotAuthError("BAD_AGENT_URL", f"unexpected path {parts.path!r}")
    return f"https://{parts.netloc}{DIRECTORY_PATH}"


def key_from_directory(directory: dict, keyid: str,
                       allow_kid_match: bool = False) -> Ed25519PublicKey:
    """Find the key the signature names, by thumbprint.

    The draft fixes keyid as the RFC 7638 thumbprint of the JWK, which makes the
    lookup self-verifying: a directory cannot hand us a key under a name that is
    not derived from the key itself. Matching a ``kid`` label instead throws that
    away, so it stays off unless a caller asks for it.
    """
    keys = directory.get("keys")
    if not isinstance(keys, list) or not keys:
        raise WebBotAuthError("BAD_DIRECTORY", "no keys")
    now = int(time.time())
    for jwk in keys:
        if not isinstance(jwk, dict):
            continue
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            continue
        x = jwk.get("x")
        if not isinstance(x, str) or not x:
            continue
        try:
            matched = jwk_thumbprint(x) == keyid
        except Exception:
            continue
        if not matched and allow_kid_match:
            matched = jwk.get("kid") == keyid
        if not matched:
            continue
        nbf, exp = jwk.get("nbf"), jwk.get("exp")
        if isinstance(nbf, int) and now + CLOCK_SKEW < nbf:
            raise WebBotAuthError("KEY_NOT_YET_VALID", keyid)
        if isinstance(exp, int) and now - CLOCK_SKEW > exp:
            raise WebBotAuthError("KEY_EXPIRED", keyid)
        try:
            raw = _b64u_decode(x)
            if len(raw) != 32:
                raise ValueError("wrong length")
            return Ed25519PublicKey.from_public_bytes(raw)
        except Exception as exc:
            raise WebBotAuthError("BAD_DIRECTORY", "unusable Ed25519 key") from exc
    raise WebBotAuthError("UNKNOWN_KEY", keyid)


class DirectoryFetcher:
    """Fetches key directories over the network, with the sharp edge contained.

    The URL is chosen by the party being authenticated, which makes any fetcher
    here a server-side request forgery primitive. The mitigations are: https
    only, the well-known path only, no redirects, a response size cap, a timeout,
    and a refusal to talk to an address that is not publicly routable.

    ``allow`` is the one that actually matters in production. Verified-agent
    hosts are a short, known list; leaving it open means the verifier will make
    an outbound request to any hostname a stranger puts in a header. The private
    address check closes the obvious hole, but it resolves the name itself and
    then hands the name to the client, so a racing DNS answer can still differ.
    An allowlist has no such gap.
    """

    def __init__(
        self,
        allow: Optional[Iterable[str]] = None,
        timeout: float = 5.0,
        max_bytes: int = 64 * 1024,
        ttl: int = 3600,
        cache_size: int = 64,
    ) -> None:
        from ubag._cache import TTLCache
        self.allow = {h.lower() for h in allow} if allow else None
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._cache = TTLCache(max_size=cache_size, ttl=ttl)

    def _check_host(self, host: str) -> None:
        host = host.lower()
        if self.allow is not None and host not in self.allow:
            raise WebBotAuthError("AGENT_NOT_ALLOWED", host)
        try:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise WebBotAuthError("DIRECTORY_UNREACHABLE",
                                  f"cannot resolve {host}") from exc
        for info in infos:
            addr = ipaddress.ip_address(info[4][0])
            if (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
                raise WebBotAuthError("PRIVATE_ADDRESS", f"{host} resolves to {addr}")

    def __call__(self, signature_agent: str) -> dict:
        url = directory_url(signature_agent)
        cached = self._cache.get(url)
        if cached is not None:
            return cached
        self._check_host(urlsplit(url).hostname or "")
        import httpx
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:
                with client.stream("GET", url,
                                   headers={"Accept": DIRECTORY_CONTENT_TYPE}) as response:
                    if response.status_code != 200:
                        raise WebBotAuthError("DIRECTORY_UNREACHABLE",
                                              f"HTTP {response.status_code}")
                    body = b""
                    for chunk in response.iter_bytes():
                        body += chunk
                        if len(body) > self.max_bytes:
                            raise WebBotAuthError("DIRECTORY_TOO_LARGE", url)
        except WebBotAuthError:
            raise
        except Exception as exc:
            raise WebBotAuthError("DIRECTORY_UNREACHABLE", str(exc)) from exc
        try:
            directory = json.loads(body)
        except ValueError as exc:
            raise WebBotAuthError("BAD_DIRECTORY", "not JSON") from exc
        if not isinstance(directory, dict):
            raise WebBotAuthError("BAD_DIRECTORY", "not an object")
        self._cache.set(url, directory)
        return directory


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_web_bot_auth(
    method: str,
    url: str,
    headers: dict,
    resolve_directory: Callable[[str], dict] | dict,
    require_expires: bool = True,
    max_age: int = MAX_AGE,
    skew: int = CLOCK_SKEW,
    require_tag: bool = True,
    allow_kid_match: bool = False,
) -> VerifiedAgent:
    """Verify one Web Bot Auth signature, or raise ``WebBotAuthError``.

    ``resolve_directory`` is either the directory itself or a callable taking the
    Signature-Agent URL. Nothing in here reaches the network on its own.

    Returns identity only. Deciding what that identity may do is the gateway's
    job, and keeping the two apart is why a signed agent still cannot act outside
    its tier.
    """
    try:
        raw_input = _field_value(headers, SIGNATURE_INPUT_HEADER.lower())
        raw_sig = _field_value(headers, SIGNATURE_HEADER.lower())
    except WebBotAuthError:
        raise WebBotAuthError("NOT_SIGNED",
                              "Signature and Signature-Input are both required")

    inputs = parse_signature_input(raw_input)
    signatures = {label: _bare_item(value)
                  for label, value in _parse_dictionary(raw_sig)}

    candidates = [label for label, (_c, params, _r) in inputs.items()
                  if not require_tag or dict(params).get("tag") == TAG]
    if not candidates:
        raise WebBotAuthError("NO_WEB_BOT_AUTH_SIGNATURE",
                              f'no signature tagged "{TAG}"')

    last = WebBotAuthError("NO_WEB_BOT_AUTH_SIGNATURE")
    for label in candidates:
        try:
            return _verify_one(
                label, inputs[label], signatures.get(label), method, url, headers,
                resolve_directory, require_expires, max_age, skew, allow_kid_match,
            )
        except WebBotAuthError as exc:
            last = exc
    raise last


def _verify_one(
    label: str,
    parsed: tuple[tuple[str, ...], list[tuple[str, Any]], str],
    signature: Any,
    method: str,
    url: str,
    headers: dict,
    resolve_directory: Callable[[str], dict] | dict,
    require_expires: bool,
    max_age: int,
    skew: int,
    allow_kid_match: bool,
) -> VerifiedAgent:
    components, param_list, raw_params = parsed
    params = dict(param_list)

    if not isinstance(signature, bytes):
        raise WebBotAuthError("MISSING_SIGNATURE", label)
    if len(signature) != 64:
        raise WebBotAuthError("BAD_SIGNATURE",
                              f"Ed25519 is 64 bytes, got {len(signature)}")

    for name in REQUIRED_COMPONENTS:
        if name not in components:
            raise WebBotAuthError("COMPONENT_NOT_COVERED", name)
    for name in components:
        if name.startswith("@") and name not in _DERIVED:
            raise WebBotAuthError("UNSUPPORTED_COMPONENT", name)

    alg = params.get("alg")
    if alg is not None and str(alg).lower() != ALG:
        raise WebBotAuthError("UNSUPPORTED_ALG", str(alg))

    keyid = params.get("keyid")
    if not isinstance(keyid, str) or not keyid:
        raise WebBotAuthError("MISSING_KEYID", label)

    now = int(time.time())
    created, expires = params.get("created"), params.get("expires")
    if created is not None:
        if not isinstance(created, int) or isinstance(created, bool):
            raise WebBotAuthError("BAD_TIMESTAMP", "created must be an integer")
        if created > now + skew:
            raise WebBotAuthError("NOT_YET_VALID", f"created {created} is in the future")
    if expires is None:
        if require_expires:
            raise WebBotAuthError(
                "MISSING_EXPIRES",
                "a signature with no expiry is a permanent bearer token")
    else:
        if not isinstance(expires, int) or isinstance(expires, bool):
            raise WebBotAuthError("BAD_TIMESTAMP", "expires must be an integer")
        if expires + skew < now:
            raise WebBotAuthError("EXPIRED", f"expired at {expires}")
        if created is not None:
            if expires <= created:
                raise WebBotAuthError("BAD_TIMESTAMP", "expires is not after created")
            if expires - created > max_age:
                raise WebBotAuthError("WINDOW_TOO_LONG",
                                      f"{expires - created}s exceeds {max_age}s")

    nonce = params.get("nonce")
    if nonce is not None:
        if not isinstance(nonce, str):
            raise WebBotAuthError("BAD_NONCE", "nonce must be a string")
        try:
            decoded = _b64_any(nonce)
        except Exception as exc:
            raise WebBotAuthError("BAD_NONCE", "not base64") from exc
        if len(decoded) < NONCE_MIN_BYTES:
            raise WebBotAuthError("BAD_NONCE",
                                  f"under {NONCE_MIN_BYTES} bytes of entropy")

    # Signature-Agent carries the key location, and if sent it must be signed.
    # Otherwise an intermediary could swap the directory for one it controls and
    # the signature would still check out, against the attacker's key.
    agent_header: Optional[str] = None
    for key, value in headers.items():
        if key.lower() == SIGNATURE_AGENT_HEADER.lower():
            agent_header = value if isinstance(value, str) else ", ".join(value)
            break
    if agent_header is not None and "signature-agent" not in components:
        raise WebBotAuthError("AGENT_NOT_COVERED",
                              "Signature-Agent was sent but not signed")
    if agent_header is None and not isinstance(resolve_directory, dict):
        raise WebBotAuthError("NO_AGENT_URL",
                              "Signature-Agent is required to locate keys")

    # With no Signature-Agent there is no URL to be, and the identity is simply
    # whoever holds the key. Naming that explicitly keeps the field from coming
    # back empty, because an empty issuer is one typo in a policy table away from
    # matching every unidentified caller.
    if agent_header:
        issuer = _unquote(agent_header.strip())
        directory_url(issuer)  # reject a bad URL before any signature work
    else:
        issuer = f"urn:ubag:keyid:{keyid}"

    directory = (resolve_directory if isinstance(resolve_directory, dict)
                 else resolve_directory(issuer))
    public = key_from_directory(directory, keyid, allow_kid_match=allow_kid_match)

    # Verify against the bytes as received first, then against a canonical
    # re-serialization. Signers differ in their whitespace, and the bytes they
    # hashed are the bytes they sent, so preferring the received form is what
    # makes this verify real traffic rather than only its own test vectors.
    bases = [signature_base(components, raw_params, method, url, headers)]
    canonical = _serialize_params(components, param_list)
    if canonical != raw_params:
        bases.append(signature_base(components, canonical, method, url, headers))
    for base in bases:
        try:
            public.verify(signature, base)
            break
        except InvalidSignature:
            continue
    else:
        raise WebBotAuthError("BAD_SIGNATURE",
                              "no covered-component serialization verified")

    return VerifiedAgent(
        issuer=issuer,
        keyid=keyid,
        nonce=nonce if isinstance(nonce, str) else None,
        created=created if isinstance(created, int) else None,
        expires=expires if isinstance(expires, int) else None,
        label=label,
        components=components,
    )


# ---------------------------------------------------------------------------
# Signing, so our own agents can carry the passport, and so the verifier above
# can be tested against something other than its own assumptions
# ---------------------------------------------------------------------------

def public_jwk(private: Ed25519PrivateKey) -> dict:
    from cryptography.hazmat.primitives import serialization
    raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(raw)}


def build_directory(privates: Iterable[Ed25519PrivateKey]) -> dict:
    """The JWKS to serve at the well-known path."""
    return {"keys": [public_jwk(p) for p in privates]}


def sign_request(
    private: Ed25519PrivateKey,
    method: str,
    url: str,
    signature_agent: str,
    headers: Optional[dict] = None,
    ttl: int = 300,
    label: str = "sig1",
    nonce: Optional[str] = None,
    extra_components: Iterable[str] = (),
) -> dict:
    """Return the headers that make a request a Web Bot Auth request."""
    import os
    out = dict(headers or {})
    out[SIGNATURE_AGENT_HEADER] = f'"{signature_agent}"'
    components = ["@authority", "signature-agent", *extra_components]
    now = int(time.time())
    params: list[tuple[str, Any]] = [
        ("created", now),
        ("expires", now + ttl),
        ("keyid", jwk_thumbprint(public_jwk(private)["x"])),
        ("alg", ALG),
        ("nonce", nonce or _b64u(os.urandom(64))),
        ("tag", TAG),
    ]
    serialized = _serialize_params(components, params)
    base = signature_base(components, serialized, method, url, out)
    out[SIGNATURE_INPUT_HEADER] = f"{label}={serialized}"
    out[SIGNATURE_HEADER] = f"{label}=:{_b64u(private.sign(base))}:"
    return out
