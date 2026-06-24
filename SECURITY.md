# Security

UBAG is a **pre-1.0, unaudited** implementation of an agent-identity protocol.
The cryptographic design is deliberate, but the code has not had a third-party
security review. Read this before relying on it in production.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue.
Email: `medhmida1990@gmail.com` with subject `UBAG SECURITY`. Expect an
acknowledgement within a few days. Coordinated disclosure appreciated.

## What UBAG protects

- **Agent identity is a keypair, not a claim.** An agent proves *who it is* by
  signing the site's nonce with its Ed25519 **private** key; the site verifies
  with the **public** key. Knowing a shared secret never grants identity — only
  the holder of the private key can pass Branch C.
- **Credentials need no shared secret to verify.** Credentials are ES256 JWTs
  signed by the issuer's EC P-256 private key and verified with its public key
  (publishable as JWKS). Any independent site can validate without holding a
  secret — the OAuth/OIDC model.
- **Nonces are one-time and tamper-evident.** Each challenge nonce carries a
  server-side HMAC stamp (the server signing to itself, for stateless issuance)
  and is marked used after a successful verify, so a replayed nonce is rejected.
- **Proof-of-possession is available.** Credentials bind to the agent's identity
  key via the `cnf` claim, so a verifier *can* require the bearer to prove it
  still holds the matching private key.

## What UBAG does NOT protect against (current limitations)

These are real and intentional to state — do not assume otherwise:

- **Identity ≠ trustworthiness.** UBAG proves *which key* an agent holds,
  consistently. It does **not** vouch that the agent is benign. Anyone can
  generate an agent key. There is no trust root, PKI, or reputation layer yet.
- **Replay protection is single-process by default.** The built-in nonce store
  is in-memory. In any multi-process / multi-instance deployment you **must**
  supply a shared store (Redis/DB) or a used nonce can be replayed against a
  different process within its TTL.
- **No credential revocation yet.** The only mitigation for a leaked credential
  is its short TTL (default 300s). There is no revocation list or `cnf`
  enforcement by default — a stolen, unexpired credential can be replayed unless
  you enforce proof-of-possession yourself.
- **No built-in rate limiting** on `/ubag/verify`. Signature forgery is
  infeasible, but the endpoint can be hammered. Put it behind your own rate
  limiter / WAF.
- **Set `server_secret` explicitly.** If you don't, a default stamping key is
  derived deterministically — fine for local testing, **not** for production.
  Use a strong random value (and the same value across your instances).
- **Branch A is a transparent proxy.** Confirm its upstream TLS and origin
  handling match your trust assumptions before exposing it publicly.
- **Pre-1.0 wire format.** Header names, claim shapes, and the challenge body
  may change before 1.0. Pin a version.

## Scope

Defaults are tuned for clarity and local development, not hostile production
traffic. Treat this as a reference implementation you harden and review for your
own deployment — not a turnkey security appliance.
