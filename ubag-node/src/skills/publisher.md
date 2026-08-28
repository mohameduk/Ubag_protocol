---
name: ubag-publisher
description: Serving a website through the UBAG web layer. Read before touching UBAG middleware config, routing branches, or the scoped-retrieval endpoint.
ubag_skill_version: 0.6.0
---

# UBAG, publisher side

This project serves a website through UBAG. UBAG sits at the web edge, works out
what kind of client is asking, and routes accordingly:

| branch | who | what they get |
|---|---|---|
| A | humans | your origin, proxied, unchanged |
| B | credentialed agents | auto-extracted JSON-LD plus a labeled Markdown layer |
| C | unidentified automation | a cryptographic challenge |

Identity and authorization are deliberately separate. Verifying *who an agent is*
is cryptography. Deciding *whether it may read this site* is the publisher's
policy. Never merge the two.

## Mounting it

Python, FastAPI or Starlette:

```python
from fastapi import FastAPI
from ubag import UBAGMiddleware, generate_issuer_keypair

issuer_private, _ = generate_issuer_keypair()   # EC P-256 (ES256)
trusted_agents = {"ubag:some-approved-agent-id"}

app = FastAPI()
app.add_middleware(
    UBAGMiddleware,
    origin="https://yoursite.com",
    issuer_key=issuer_private,
    server_secret="a-separate-random-32+char-secret",
    authorize_agent=lambda identity, request: identity["agent_id"] in trusted_agents,
)
```

Node, Express:

```js
const { ubag, generateIssuerKeypair } = require('ubag-web');

const { privateKey: ISSUER_PRIVATE } = generateIssuerKeypair();
const trustedAgents = new Set(['ubag:some-approved-agent-id']);

app.use(express.json());
app.use(ubag({
  origin: 'https://yoursite.com',
  issuerKey: ISSUER_PRIVATE,
  serverSecret: 'a-separate-random-32+char-secret',
  authorizeAgent: ({ agentId }) => trustedAgents.has(agentId),
}));
```

The npm package is `ubag-web` (npm reserves the bare name). The PyPI package is
`ubag`. Same protocol, identical wire format, cross-verifiable.

Mounted, the site also exposes `/.well-known/ubag.json` for discovery and
`/.well-known/jwks.json` for the issuer key.

## Two keys, two jobs

`issuer_key` mints and verifies credentials. `server_secret` is separate and must
stay separate. They are not interchangeable and reusing one for both collapses
the security model. Neither belongs in source control.

## The scoped layer

Any resource served through UBAG answers these on its own URL:

```
?ubag.fields=offers.price,offers.availability   only those typed fields
?ubag.manifest=1                                what this resource can answer
?ubag.profile=auto                              expand each field to its entity
?ubag=lean                                      drop the response envelope
?ubag=compact                                   full facts, less duplication
```

This half is not gated and is not meant to be. An agent identity is worth more
the more sites answer one, so a scoped endpoint locked to a single vendor is
worth nothing to anybody.

## Rules that are load-bearing

**No model runs in the scoped path.** Resolution is deterministic lookup over
the publisher's own structured data. An endpoint that interpreted natural
language would move the caller's inference cost onto this server, which is the
exact cost the layer exists to remove. If you are about to add an LLM call
inside resolve, stop.

**Misses are reported, never guessed.** A field that cannot be resolved comes
back under `ubag:unresolved`. An agent has to be able to tell "this resource says
nothing about price" from "the price is nothing". Blurring those two produces
confident wrong answers downstream, and it is not recoverable once shipped.

**Control parameters never reach the origin.** `?ubag.*` is stripped before
proxying. Forwarding it upstream is at best ignored and at worst poisons a cache
key.

**`site_meta` / `siteMeta` is optional.** Branch B auto-extracts JSON-LD,
OpenGraph and meta tags from the origin's own HTML. Pass it only to override.
Do not hand-write metadata that the extractor already produces.

**`authorize_agent` is a policy hook, not an identity check.** By the time it is
called, the identity is already cryptographically established. Returning true
unconditionally is a valid choice for an open site, but make it a deliberate one.

## If this deployment has a behavioural or scoring layer

Some deployments run additional client classification behind environment flags.
Where those exist:

- A flag defaults to logging, not enforcing. Changing a default to enforce is
  never part of an unrelated change.
- No flag flips without first reading the shadow counter on a host that actually
  receives human traffic. A host with no organic visitors cannot produce a
  meaningful false-positive count, and its clean report is not evidence.
- Challenging a real visitor costs the site owner more than serving a scraper
  does. Every ambiguous case resolves toward serving the visitor.

## Status

Pre-1.0 and unaudited. See SECURITY.md in the protocol repo before deploying
anywhere that matters: https://github.com/mohameduk/Ubag_protocol
