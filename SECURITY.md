# Security

UBAG is a **pre-1.0, unaudited** implementation of an agent-identity and web-routing
protocol. The cryptographic design is deliberate, but the project has not yet had
an independent third-party security review. Treat it as a reference implementation
that requires deployment-specific review and hardening.

## Reporting a vulnerability

Report security issues **privately** rather than opening a public issue. Email
`medhmida1990@gmail.com` with the subject `UBAG SECURITY`. We aim to acknowledge
reports within a few days and appreciate coordinated disclosure.

## Security properties

- **Identity is key possession, not a self-asserted name.** An agent signs a
  time-bound nonce with its Ed25519 private key. The site verifies the signature
  with the supplied public key and derives the stable agent identifier from that key.
- **Identity verification is separate from authorization.** A valid challenge
  proves control of an identity key. It does not issue a credential by default.
  A site must approve the identity through `authorize_agent` / `authorizeAgent`,
  or explicitly enable self-registration for a low-trust deployment.
- **Credentials are asymmetrically signed.** ES256 JWTs are signed by the issuer's
  EC P-256 private key and verified with a configured trusted public key. Tokens
  carry and validate `iss`, `aud`, `sub`, `iat`, `exp`, and `jti` claims.
- **Credentials are holder-of-key by default.** Every credentialed request requires
  a v2 Ed25519 proof covering the method, host, path plus query, credential
  thumbprint, timestamp, and a unique proof identifier. The proof identifier is
  consumed to reject replay inside the freshness window.
- **Credential path grants are enforced.** The middleware checks the token's
  `paths` claim before serving Branch B.
- **Challenge replay is bounded and one-time.** Successful nonce redemption is
  recorded through an atomic `consume` operation. The built-in store is bounded,
  TTL-aware, and safe for a single process.
- **Nonce stamping and credential signing use separate secrets.** A strong
  `server_secret` / `serverSecret` is required. The middleware no longer derives
  the HMAC stamping secret from the issuer private key.
- **Upstream TLS verification is enabled by default.** Disable it only for an
  explicitly trusted development or private origin.

## Current limitations

- **Identity is not trustworthiness.** Anyone can generate an Ed25519 keypair.
  UBAG establishes continuity of identity; reputation, ownership, attestation,
  and behavioral trust require an authorization policy or external trust service.
- **Self-registration is an explicit low-trust mode.** Enabling
  `allow_self_registration=True` / `allowSelfRegistration: true` issues a
  `self_asserted_agent` credential after key verification. Do not treat that
  credential as organizational vetting.
- **Issuer trust is configured, not automatic.** Publishing JWKS makes signature
  verification possible, but another site must still decide to trust that issuer
  and configure the expected issuer, audience, and public key.
- **The default replay and rate-limit stores are process-local.** Multi-process or
  multi-instance deployments need a shared adapter whose `consume` operation is
  atomic across instances. The built-in verification rate limiter is also local.
- **Revocation is callback-based.** Tokens are short-lived (five minutes by
  default), and applications can provide `is_credential_revoked` /
  `isCredentialRevoked`. A hosted or distributed revocation service is not built in.
- **PoP v2 does not cover a request-body digest.** It is suitable for the current
  read-oriented Web Layer. Deployments authorizing state-changing requests should
  add a body-aware HTTP Message Signature policy before treating it as transaction
  authorization.
- **The browser-versus-machine classifier is not a security boundary.** User-Agent
  and Accept headers can be spoofed. Branch classification controls presentation
  and challenge flow; credentials and authorization policy control agent access.
- **`/ubag/verify` protection is intentionally basic.** The SDK applies a bounded
  request-size limit and a process-local rate limit. Internet-facing deployments
  should still use an edge rate limiter or WAF.
- **Site-declared data is attributable, not independently verified.** JSON-LD,
  OpenGraph, and metadata come from the origin site. UBAG labels provenance but
  cannot guarantee that the publisher's claims are factually true.
- **Branch A is a transparent proxy.** Review upstream TLS, trusted proxy headers,
  origin redirects, caching, and SSRF assumptions for the deployment environment.
- **The wire format is pre-1.0.** Header names, claims, challenge bodies, and proof
  formats may change. Pin a package version.

## Production checklist

- Configure a strong, separate `server_secret` / `serverSecret` of at least 32 characters.
- Persist issuer private keys in a managed key service or secret store.
- Keep proof-of-possession enabled.
- Provide an explicit authorization callback; leave self-registration disabled.
- Configure expected issuer and audience values.
- Use shared atomic replay storage and distributed rate limiting for multiple instances.
- Connect the revocation callback to your policy or credential-control service.
- Restrict credential path grants to the minimum required routes.
- Place the verification endpoint behind request-size and edge rate controls.
- Complete an independent security review before production use.
