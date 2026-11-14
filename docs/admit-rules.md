# waftoken admit rules

## Signing input
`v1|{kid}|{method}|{host}|{path}|{body_sha256}|{iat}|{exp}|{nonce}`

## Gates
1. HMAC + kid_revoked.
2. host allowlist exact.
3. method allowlist.
4. path must start with path_allow_prefixes AND must not start with denied_path_prefixes.
5. if method in require_body_hash_for: body_sha256 must be 64-hex.
6. time window + nonce store (allow-only write).
