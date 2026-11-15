# gitrefx admit rules

## Signing input
`v1|{kid}|{ref}|{old_oid}|{new_oid}|{actor}|{force_0_1}|{iat}|{nonce}`

## Ref normalize / safety
Reject if ref contains `..` or `//` => `ref_unsafe`.
Ref must start with allowed_ref_prefixes; must not equal denied_ref_names.

## Gates
1. HMAC + kid_revoked; actor ∈ actors.
2. oid length oid_hex_len hex; if forbid_delete and new_oid all-zero => deny.
3. if force and ref startswith protect_prefixes: actor must ∈ force_require_actors.
4. time + nonce allow-only.
