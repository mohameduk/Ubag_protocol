# ubag (Node)

**UBAG Web Layer — agent identity and routing at the web edge.** Express middleware.

When an autonomous agent visits a website, UBAG verifies *who it is* and routes
accordingly: humans to your normal site, credentialed agents to clean JSON-LD,
unknown bots to a cryptographic challenge. Asymmetric by design — agent identity
is an Ed25519 keypair; credentials are ES256 JWTs verifiable via JWKS, no shared
secrets.

> Early but real, pre-1.0, unaudited. See the
> [full README](https://github.com/mohameduk/Ubag_protocol#readme) and
> [SECURITY.md](https://github.com/mohameduk/Ubag_protocol/blob/main/SECURITY.md).

## Install

```bash
npm install ubag-web
```

> The npm package is **`ubag-web`** (npm reserves the bare `ubag`); the Python
> package is **`ubag`** (`pip install ubag`). Same protocol, identical wire format.

## Quick start

```js
const express = require('express');
const { ubag, generateIssuerKeypair } = require('ubag-web');

const { privateKey: ISSUER_PRIVATE } = generateIssuerKeypair();  // EC P-256 (ES256)

const app = express();
app.use(ubag({
  origin: 'https://yoursite.com',
  issuerKey: ISSUER_PRIVATE,
  // siteMeta is OPTIONAL — Branch B auto-extracts structured data from your
  // origin's HTML (JSON-LD/OpenGraph/meta). Pass siteMeta only to override.
}));
```

Your site now serves credentialed agents **auto-extracted** JSON-LD plus a labeled
Markdown content layer (no hand-written metadata), proxies humans to your origin,
challenges unknown bots, exposes `/.well-known/ubag.json` for discovery, and
serves its issuer key as JWKS at `/.well-known/jwks.json`. Credentials are
holder-of-key: agents attach a per-request proof-of-possession via
`agent.headers(method, path)`.

A Python/FastAPI SDK with an identical, cross-verifiable wire format is in the
same repo. Full docs, a runnable demo, and the protocol details:
**https://github.com/mohameduk/Ubag_protocol**

MIT licensed.
