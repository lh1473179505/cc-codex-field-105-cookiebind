# gitlfsx admit rules

## Signing
`v1|{kid}|{oid}|{size}|{repo}|{path}|{iat}|{nonce}`

repo ∈ repos; path startswith path_prefixes; reject path deny; size<=size_max; oid startswith oid_prefix and hex len oid_hex_len; HMAC+revoke; time; nonce allow-only.
