# Verification

Verification order is normative so independent SDKs return compatible internal
failure codes, including for inputs with several simultaneous faults:

1. Enforce compact-envelope and decoded-component size limits.
2. Parse the protected header and payload as strict JSON objects.
3. Reject floating-point and unsafe-integer JSON values.
4. Require JCS-canonical protected-header bytes, then payload bytes.
5. Apply the protected-header allowlist.
6. Reject forbidden payload identity fields, then other unknown payload fields.
7. Validate protected `typ`, `alg`, and Ed25519 JWK shape.
8. Verify the signature with the carried key.
9. Validate required claims, types, lifetime, and clock window.
10. Compare method, public `htu`, exact origin-form hash, and Content-Digest.
11. Validate credential presence, `ath`, issuer/audience, expiry, and `cnf.jkt`
   binding when a credential is present.
12. Validate a required server nonce when the server requested one.
13. Atomically consume `(trusted public origin, verified key reference, jti)` until
   `exp + clock_skew + 1 second`.

The verifier returns `VerifiedProvenance` only after every step succeeds.
Detailed codes belong in internal audit. An HTTP surface MAY map them to a
smaller public error vocabulary to avoid creating an oracle.

| Code | Meaning |
|---|---|
| `MALFORMED_ENVELOPE` | Compact JWS or strict JSON is malformed |
| `UNSUPPORTED_PROFILE` | `typ`, `alg`, critical header, or JWK shape is unsupported |
| `INVALID_SIGNATURE` | The carried key did not verify the exact JWS signing input |
| `KEY_HINT_MISMATCH` | Optional `kid` differs from the verified-key reference |
| `INVALID_CLAIMS` | Required claims, types, or lifetime are invalid |
| `PROOF_EXPIRED` | The proof is outside the bounded clock window |
| `METHOD_MISMATCH` | `htm` differs from the request |
| `ORIGIN_MISMATCH` | `htu` differs from the configured public origin and path |
| `TARGET_MISMATCH` | Exact origin-form digest differs |
| `CONTENT_DIGEST_MISMATCH` | RFC 9530 digest differs from the raw body |
| `CREDENTIAL_MISMATCH` | Credential absence, `ath`, validity, audience, or key binding differs |
| `VERIFIER_MISCONFIGURED` | A presented credential cannot be checked because no validator is configured |
| `NONCE_MISMATCH` | A required server nonce is absent or incorrect |
| `PROVENANCE_REPLAYED` | Atomic `jti` consumption failed |
| `REPLAY_KEY_QUOTA_EXCEEDED` | One `(public origin, verified key)` namespace reached its live-entry quota |
| `REPLAY_ORIGIN_QUOTA_EXCEEDED` | One trusted public origin reached its live-entry quota |
| `REPLAY_STORE_EXHAUSTED` | Global replay storage is full of live entries; verification fails closed |

Replay storage TTL is `exp + clock_skew + 1 second`. A production multi-instance verifier
requires a shared store with an atomic consume-if-absent operation.
Stores MUST NOT evict unexpired replay identifiers. Capacity exhaustion is a
fail-closed availability event and SHOULD emit an operator metric or alert.
Implementations MUST contain a single verified key with a per-key live-entry
quota, isolate each trusted public origin with an origin-level quota, and retain
a global bound against key rotation. The global capacity
must be sized from peak request rate, retention, and an operational safety
factor; the in-memory SDK defaults are not production sizing guidance.

Tier bounds MUST be sized so that origin isolation still holds at the
deployment's active-origin count:

```
global_bound >= expected_active_origins * per_origin_bound
```

When the global bound is smaller than the aggregate the per-origin bounds may
admit, the global tier becomes the binding constraint before origin quotas ever
engage, and origin isolation silently degrades to a shared limit under broad
load. The in-memory SDK defaults (global `100000`, origin `20000`, key `4096`)
satisfy the invariant only up to five concurrently saturated origins; a
deployment serving more MUST raise the global bound or lower the per-origin
bound.

Only key-namespace exhaustion MAY carry the key-derived `agent_ref` as the
responsible namespace. Origin or global exhaustion MUST NOT attribute causality
to the request that happened to encounter a previously exhausted bound. None of
these failures creates `VerifiedProvenance`: replay verification did not
complete. Metrics SHOULD keep bounded labels; raw agent references belong in
audit events rather than unbounded time-series dimensions.

An HTTP deployment SHOULD map key- or origin-quota exhaustion to `429 Too Many
Requests` with a bounded `Retry-After`. Global storage exhaustion is an
operator-capacity fault and SHOULD map to `503 Service Unavailable`.

Custom namespace and group extractors MUST be deterministic and pure for a
given identifier. SDK stores nevertheless clamp missing decrement counters so
an impure integration fails conservatively instead of crashing expiry cleanup.
