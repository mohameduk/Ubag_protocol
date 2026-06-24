# UBAG Protocol

**The missing identity layer for MCP agents.**

MCP solved how agents communicate. UBAG solves who the agent is — and what happens to everyone else.

---

## The Problem

When an autonomous MCP agent visits a website today:

- The website has no way to verify who it is
- It scrapes raw HTML like any bot from 2005
- Unknown agents get blocked by Cloudflare — including legitimate ones
- No human is in the loop to click "Allow"

MCP's OAuth 2.1 spec is built for human-delegated auth (browser → redirect → user clicks Allow). It does not cover **autonomous agent identity** — the credential an agent carries when no human is in the loop.

UBAG fills that gap.

---

## How It Works

Every request to a UBAG-enabled website is routed through a 3-branch matrix:

```
Incoming request
        │
        ▼
┌───────────────────┐
│  UBAG Web Layer   │
└───────────────────┘
        │
        ├── Has valid UBAG credential?  ──► Branch B: Clean JSON-LD data
        │                                   Fast. Structured. No scraping.
        │
        ├── Looks human?  ───────────────► Branch A: Transparent proxy
        │                                   Origin server, untouched.
        │
        └── Unknown agent?  ─────────────► Branch C: Sandbox + challenge
                                            Sign a nonce with your key (Ed25519).
                                            Prove identity → get credentialed.
```

**Branch B is the key insight.** Instead of an agent crawling 50 pages to understand a business, UBAG serves one structured JSON-LD response with everything — products, prices, policies, contacts. One request. No parsing. No hallucination from bad HTML.

---

## Security Model

UBAG is **asymmetric — there are no shared secrets:**

- **Agent identity = an Ed25519 keypair.** An agent's identity is the SHA-256 thumbprint of its public key (`ubag:…`). To get in, the agent signs the site's nonce with its *private* key; the site verifies with the *public* key. Only the holder of the key can pass — knowing a shared secret never establishes *who* an agent is.
- **Credentials = ES256 JWTs** signed by an issuer's EC P-256 private key and verifiable by any site with the issuer's *public* key (publishable as JWKS at `/.well-known/jwks.json`). No site needs a secret to validate a credential — the same model as OAuth / OIDC, which is what lets one credential work across independent sites.
- **Proof-of-possession ready.** Each credential binds to the agent's key via the `cnf` claim, so a verifier can require the bearer to prove it still holds the matching private key.

The Python and Node SDKs share identical wire formats (raw Ed25519 + ES256), so a signature or credential produced by one verifies in the other.

---

## Quick Start

```bash
pip install ubag
```

```python
from fastapi import FastAPI
from ubag import UBAGMiddleware, generate_issuer_keypair

# Your site is its own credential issuer. Generate once and persist these
# (or run verify-only by passing issuer_public_key alone).
ISSUER_PRIVATE, ISSUER_PUBLIC = generate_issuer_keypair()   # EC P-256 (ES256)

app = FastAPI()
app.add_middleware(
    UBAGMiddleware,
    origin="https://yoursite.com",
    issuer_key=ISSUER_PRIVATE,   # mints + verifies agent credentials
)
```

That's it. Your site now:

- ✅ Serves clean JSON-LD to credentialed MCP agents (Branch B)
- ✅ Proxies humans transparently to your origin (Branch A)  
- ✅ Sandboxes unknown bots with a cryptographic challenge (Branch C)
- ✅ Exposes `yoursite.com/agents.json` for MCP agent discovery
- ✅ Logs every agent visit with branch, IP, and path

---

## For MCP Agent Developers

If you're building an MCP agent that visits websites, get a UBAG credential:

```python
from ubag import AgentCredential

# Your agent's identity IS its Ed25519 keypair. Generate once; persist agent.export().
agent = AgentCredential.generate(owner="you@email.com")

# When a UBAG site challenges you (HTTP 429), sign the nonce and post it back:
#   challenge = resp.json()["ubag_challenge"]
#   solution  = agent.solve_challenge(challenge)     # signs the nonce with your private key
#   r = httpx.post(f"{site}/ubag/verify", json=solution)
#   agent.set_credential(r.json()["credential"])

# Once credentialed, it travels with every request:
headers = agent.headers()
# {"X-UBAG-Credential": "eyJ..."}
```

UBAG-enabled sites will recognize your agent and serve structured data instead of HTML. Your agent gets better data. The website owner gets visibility and control.

---

## agents.json

Every UBAG-enabled site automatically serves `/agents.json`:

```json
{
  "ubag_version": "1.0",
  "credential_endpoint": "https://ubagprotocol.com/credential",
  "branches": {
    "authorized_agents": "Branch B — JSON-LD structured data",
    "humans": "Branch A — transparent proxy to origin",
    "unknown": "Branch C — cryptographic sandbox challenge"
  },
  "contact": "admin@yoursite.com"
}
```

MCP agents can discover this before making requests — similar to `robots.txt` but machine-actionable.

---

## Why Not Just Use Cloudflare?

| | Cloudflare | AWS WAF | UBAG |
|---|---|---|---|
| Blocks unknown bots | ✅ | ✅ | ❌ Challenges them |
| Clean structured data for agents | ✅ Markdown | ❌ | ✅ JSON-LD |
| Agent identity / credential | ❌ | ❌ | ✅ |
| Autonomous agent support (no browser) | ❌ | ❌ | ✅ |
| Payment to website owner | ❌ | ✅ Crypto | 🔜 |
| Open source | ❌ | ❌ | ✅ |
| Vendor lock-in | Cloudflare | AWS | None |

Cloudflare and AWS block or charge bots. UBAG **graduates** them — unknown agents can solve the challenge, get credentialed, and become authorized. No legitimate agent is permanently blocked.

---

## MCP Integration

UBAG is designed to complement MCP, not replace it:

- **MCP OAuth 2.1** — human-delegated auth (user clicks Allow in browser)
- **UBAG credential** — autonomous agent identity (no human in the loop)

```
MCP Agent
    │
    ├── Talking to MCP servers?  ──► Use MCP OAuth 2.1
    │
    └── Visiting websites?  ────────► Use UBAG credential
```

UBAG credential is issued once, verified in milliseconds at the edge, and works on any UBAG-enabled site without a redirect or browser flow.

---

## Architecture

```
ubag-python/          Python middleware (FastAPI, Django, Flask)
ubag-node/            Node.js middleware (Express, Next.js)
ubag-wordpress/       WordPress plugin
ubag-docker/          Full reference implementation (Docker Compose)
docs/
  spec/
    agents-json.md    agents.json format spec
    credential.md     Credential format + verification
    routing-matrix.md The 3-branch routing matrix
```

---

## Reference Implementation

The `ubag-docker` directory contains the full production-ready implementation:

- FastAPI application
- PostgreSQL (audit log, domain registry)
- nginx (SSL termination, routing)
- PowerDNS (optional — for nameserver delegation)
- Certbot (automatic SSL via Let's Encrypt)
- Auto-provisioner (detects DNS changes, issues SSL automatically)

Deploy on any VPS in minutes:

```bash
git clone https://github.com/ubagprotocol/ubag_protocol
cd ubag_protocol/ubag-docker
cp .env.example .env  # add your config
docker compose up -d
```

---

## Status

- [x] Branch A — Human transparent proxy
- [x] Branch B — Agent JSON-LD structured data
- [x] Branch C — Sandbox + cryptographic challenge
- [x] Auto-provisioner — DNS detection + SSL issuance
- [x] agents.json — Auto-served on every UBAG site
- [x] Audit log — Every agent visit logged
- [ ] pip install ubag — Python middleware package
- [ ] npm install ubag — Node.js middleware package
- [ ] Credential registry — ubagprotocol.com/credential
- [ ] Payment layer — Website owner revenue share

---

## Contributing

PRs welcome. The goal is to make UBAG the standard credential layer for autonomous MCP agents — open, verifiable, and not owned by any cloud provider.

---

## Contact

Built by Mohamed Ben Hadj Hmida  
[ubagprotocol.com](https://ubagprotocol.com) · [github.com/mohameduk/Ubag_protocol](https://github.com/mohameduk/Ubag_protocol)
