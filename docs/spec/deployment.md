# Reverse-proxy deployment

The verifier reconstructs `htu` from configured public-origin state, not from
arbitrary `Host`, `Forwarded`, or `X-Forwarded-*` headers.

Every deployment MUST configure:

- canonical public scheme and authority;
- trusted proxy address ranges or authenticated proxy identities;
- trusted hop count when forwarded headers are used;
- whether forwarded headers are accepted at all;
- rejection behavior for conflicting or malformed forwarding data.

The exact origin-form used for `ubag_qsh` is the public request target received
at the verification boundary: HTTP/1.1 origin-form or HTTP/2/3 `:path`.
Intermediaries between signer and verifier must preserve it byte-for-byte.
Rewriting query order or percent encoding causes a loud verification failure.

The human/agent presentation classifier remains outside this trust boundary.
Spoofable User-Agent and Accept headers never produce verified provenance or an
authoritative `SecurityContext`.

