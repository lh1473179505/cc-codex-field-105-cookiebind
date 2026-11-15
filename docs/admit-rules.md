# k8ssaid admit rules

## Signing input
`v1|{kid}|{aud}|{ns}|{sa}|{path}|{bound}|{iat}|{exp}|{nonce}`

## Path safety (before prefix allow)
Reject if path contains `..` / `%2e` / `%2E` / `//` => `path_unsafe`.

## Gates
1. HMAC + kid_revoked.
2. aud ∈ allowed_audiences; ns ∈ allowed_namespaces; sa ∈ sa_allow[ns].
3. path starts with path_allow_prefixes after safety check.
4. if require_bound: bound form `Kind/ns/name` and Kind ∈ bound_kinds; ns in bound must equal token ns.
5. time window + nonce store; write only on allow.
