# ubag (Node)

**UBAG Web Layer — agent identity and routing at the web edge.** Express middleware.

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
npm install ubag-web
```

> The npm package is **`ubag-web`** (npm reserves the bare `ubag`); the Python
> package is **`ubag`** (`pip install ubag`). Same protocol, identical wire format.

## Quick start

```js
const express = require('express');
const { ubag, generateIssuerKeypair } = require('ubag-web');

const { privateKey: ISSUER_PRIVATE } = generateIssuerKeypair();  // EC P-256 (ES256)
const trustedAgents = new Set(['ubag:replace-with-an-approved-agent-id']);

const app = express();
app.use(express.json());
app.use(ubag({
  origin: 'https://yoursite.com',
  issuerKey: ISSUER_PRIVATE,
  serverSecret: 'a-separate-random-32+char-secret',
  authorizeAgent: ({ agentId }) => trustedAgents.has(agentId),
  // siteMeta is OPTIONAL — Branch B auto-extracts structured data from your
  // origin's HTML (JSON-LD/OpenGraph/meta). Pass siteMeta only to override.
}));
```

Your site now serves credentialed agents **auto-extracted** JSON-LD plus a labeled
Markdown content layer (no hand-written metadata), proxies humans to your origin,
challenges unknown automation, exposes `/.well-known/ubag.json` for discovery, and
serves its issuer key as JWKS at `/.well-known/jwks.json`. Credentials are
holder-of-key: agents attach a one-time request-bound proof-of-possession via
`agent.headers(method, absoluteUrl)`.

## Teach your coding agent

```bash
npx ubag-web init            # you are serving a site through UBAG
npx ubag-web init --agent    # you are building an agent that reads UBAG-enabled sites
npx ubag-web init --both
```

Writes `.agents/skills/ubag-*/SKILL.md` into your project, and creates `AGENTS.md`
and `CLAUDE.md` only if they do not already exist. An `AGENTS.md` you already have
is never modified; the line to add is printed instead. Safe to re-run.

`npx ubag-web init --check` reports whether the copy in your repo is older than
the installed SDK.

A Python/FastAPI SDK with an identical, cross-verifiable wire format is in the
same repo. Full docs, a runnable demo, and the protocol details:
**https://github.com/mohameduk/Ubag_protocol**

MIT licensed.
