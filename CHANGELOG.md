# Changelog

## v0.3.0 — Security hardening

Defense-in-depth hardening of the gateway. Both SDKs (Python + Node) at parity;
CI green on Python 3.10–3.12 and Node 18–22.

> ⚠️ **Breaking change for agents.** Credentialed requests now require a
> proof-of-possession header by default. Agents built on `AgentCredential`
> should call `headers(method, path)` (which now signs the PoP automatically);
> agents hand-rolling headers must add `X-UBAG-PoP` + `X-UBAG-PoP-TS`. To keep
> the old bearer behavior during migration, construct the middleware with
> `require_pop=False` (Python) / `requirePop: false` (Node).

### Security

- **Holder-of-key credentials (proof-of-possession).** The agent branch now
  verifies a per-request Ed25519 signature over `"METHOD PATH TIMESTAMP"`
  against the key bound in the credential's `cnf` claim. A leaked or stolen
  credential is now useless without the agent's private key, closing the
  bearer-token replay window. Default on via `require_pop` / `requirePop`.
- **Upstream TLS verification on by default (Python).** The Branch A proxy now
  verifies upstream certificates (`verify_tls=True`); opt out only per trusted
  origin. (The Node proxy already verified.)
- **No predictable stamp key.** The middleware refuses to start when neither a
  server secret nor an issuer key is configured, instead of deriving a
  guessable HMAC nonce-stamp key from a known constant.

### Tests

- Adds five security regression tests per SDK: bare-bearer replay rejected,
  wrong-key PoP rejected, stale-timestamp PoP rejected, legacy bearer mode
  (`require_pop=False`) still works, and the refuse-to-start guard.

## v0.2.0 — First public release

The first public release of the **UBAG Web Layer** — the open reference
implementation of a `ubag.json` + behavioral-credential mechanism for
autonomous agents at the web edge. Two SDKs (Python + Node) with a shared,
cross-verifiable wire format.

> ⚠️ **Pre-1.0 and unaudited.** The cryptographic design is deliberate but the
> code has not had a third-party security review. Read [SECURITY.md](SECURITY.md)
> before relying on it. The wire format may change before 1.0 — pin a version.

### Highlights

- **Asymmetric identity — no shared secrets** (breaking change from v0.1's HMAC scheme):
  - Agent identity is an **Ed25519** keypair; the agent's ID is the SHA-256
    thumbprint of its public key (`ubag:…`). It proves who it is by signing the
    site's nonce with its private key.
  - Credentials are **ES256 JWTs** signed by an issuer's EC P-256 key and
    verifiable with the public key — **auto-served as JWKS at
    `/.well-known/jwks.json`**, so any independent site can validate a credential
    without holding a secret (the OAuth/OIDC model).
- **Three-branch routing**: humans → transparent proxy (A); credentialed agents
  → clean JSON-LD (B); unknown agents → cryptographic challenge (C).
- **`ubag.json`** discovery (at `/.well-known/ubag.json`, alias `/agents.json`)
  served automatically on every UBAG site — deliberately not named `agents.json`
  to avoid colliding with unrelated specs already using that filename.
- **Self-issuing by default** — a site configured with an issuer key mints
  credentials at its own `/ubag/verify`; no hosted central registry required.
- **Cross-SDK interop**: a signature or credential produced by the Python SDK
  verifies byte-for-byte in the Node SDK, and vice versa (covered by tests).
- **Runnable end-to-end demos** (`examples/demo.py`, `examples/demo.js`) that
  walk one agent through the full handshake in ~60 seconds.

### SDKs

- `ubag-python` (FastAPI / Starlette) — published on PyPI as `ubag`
- `ubag-node` (Express) — published on npm as `ubag-web`

### Install

```bash
pip install "ubag[fastapi]"   # Python
npm install ubag-web          # Node
```

### Known limitations (see SECURITY.md)

- Identity proves *which key* an agent holds — not that the agent is trustworthy.
- Built-in replay (nonce) store is in-memory / single-process; multi-instance
  deployments must supply a shared store.
- No credential revocation yet (short TTL only); no built-in rate limiting on
  `/ubag/verify`; set `server_secret` explicitly in production.
- Framework coverage today: FastAPI/Starlette and Express only. Django, Flask,
  and Next.js adapters are planned.

## v0.1.0

Initial release (Python only, HMAC-based credentials). Superseded by v0.2.0.
