# ubag (Python)

**UBAG Web Layer — agent identity and routing at the web edge.** FastAPI / Starlette middleware.

When an autonomous agent visits a website, UBAG verifies *who it is* and routes
accordingly: humans to your normal site, credentialed agents to clean JSON-LD,
unknown automation to a cryptographic challenge. Identity verification and site
authorization are separate. Asymmetric by design — agent identity
is an Ed25519 keypair; credentials are ES256 JWTs verifiable via JWKS, no shared
secrets.

> Early but real, pre-1.0, unaudited. See the
> [full README](https://github.com/mohameduk/Ubag_protocol#readme) and
> [SECURITY.md](https://github.com/mohameduk/Ubag_protocol/blob/main/SECURITY.md).

## Install

```bash
pip install "ubag[fastapi]"
```

## Quick start

```python
from fastapi import FastAPI
from ubag import UBAGMiddleware, generate_issuer_keypair

issuer_private, _ = generate_issuer_keypair()   # EC P-256 (ES256)
trusted_agents = {"ubag:replace-with-an-approved-agent-id"}

app = FastAPI()
app.add_middleware(
    UBAGMiddleware,
    origin="https://yoursite.com",
    issuer_key=issuer_private,                  # mints + verifies credentials
    server_secret="a-separate-random-32+char-secret",
    authorize_agent=lambda identity, request: identity["agent_id"] in trusted_agents,
    # site_meta is OPTIONAL — Branch B auto-extracts structured data from your
    # origin's HTML (JSON-LD/OpenGraph/meta). Pass site_meta only to override.
)
```

Your site now serves credentialed agents **auto-extracted** JSON-LD plus a labeled
Markdown content layer (no hand-written metadata), proxies humans to your origin,
challenges unknown automation, exposes `/.well-known/ubag.json` for discovery, and
serves its issuer key as JWKS at `/.well-known/jwks.json`. Credentials are
holder-of-key: agents attach a one-time request-bound proof-of-possession via
`agent.headers(method, absolute_url)`.

A Node/Express SDK with an identical, cross-verifiable wire format is in the same
repo. Full docs, a runnable demo, and the protocol details:
**https://github.com/mohameduk/Ubag_protocol**

MIT licensed.
