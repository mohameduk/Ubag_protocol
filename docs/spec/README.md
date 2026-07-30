# UBAG Provenance Profile 1.0 (Draft)

> Status: pre-1.0 draft. The wire format is not frozen.

The public protocol proves request provenance. Private resolution establishes
accountability. UBAG Core consumes only authoritative context.

## Publication scope

This public specification is limited to provenance-envelope interoperability,
verification, replay handling, and the trust boundary required to hand verified
facts to a private resolver. Customer policy evaluation, capability grants,
multi-action composition, grounding, reversibility analysis, decision logic,
attack-memory rules, and audit-storage internals are explicitly out of scope.
The references to `SecurityContext` and mandatory fail-closed states define an
interface boundary only; they do not specify the proprietary authorization
engine behind it.

This profile is based on the proof-of-possession shape defined by RFC 9449
(DPoP), but it is not a DPoP proof and is not interchangeable with one. Its
media type is `ubag-provenance+jwt`; it adds exact request-target and
RFC 9530 Content-Digest binding required by the UBAG web boundary.

The trust stages are deliberately distinct:

1. `ProvenanceEnvelope`: untrusted compact JWS bytes received from a client.
2. `VerifiedProvenance`: a verifier has established that a particular key
   signed a particular request and has consumed its replay identifier.
3. `SecurityContext`: private tenant, principal, account, credential, and
   attribution facts derived from trusted transport configuration and a
   gateway-held registry.

`tenant`, `tenant_ref`, `principal`, and `principal_ref` are forbidden wire
claims. A receiver MUST ignore neither unknown security claims nor copies of
these values: it MUST reject the envelope.

Normative details:

- [Provenance envelope](provenance.md)
- [Verification and failure codes](verification.md)
- [Private resolution boundary](resolution-boundary.md)
- [Reverse-proxy deployment](deployment.md)
- [Normative vectors](test-vectors/v1.json)
