# Private resolution boundary

This document marks where the public protocol stops. Resolution is not an
interoperable surface and is out of scope for this specification; it is named
here only so integrators know the boundary.

```text
parse(bytes)              -> ProvenanceEnvelope | ParseFailure
verify(envelope, request) -> VerifiedProvenance | VerificationFailure
resolve(verified, ...)    -> SecurityContext        (private, out of scope)
decide(context, action)   -> Decision               (private, out of scope)
```

The public protocol ends at `VerifiedProvenance`: the fact that a particular
key signed a particular request, with its replay identifier consumed. Turning
that fact into an authoritative `SecurityContext` is performed by the private
resolver in the deployment and is not specified here.

Two requirements bind any resolver, because they are what keep the trust
boundary sound:

- Tenant, principal, account, and credential ownership MUST be derived from
  trusted transport configuration and deployment-held registration. They MUST
  NOT be read from envelope claims, headers controlled by an untrusted proxy,
  tool arguments, or model text.
- Resolution MUST be total and fail closed. A verified envelope that cannot be
  resolved to an authoritative context MUST NOT reach an authorization
  decision.

Registry schema, attribution states, revocation semantics, and policy
evaluation order are deployment concerns and are deliberately not part of this
public specification.
