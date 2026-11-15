# selctx admit rules

## Signing input
`v1|{kid}|{user}|{role}|{type}|{range}|{path}|{iat}|{nonce}`

## Path
Reject deny substrings; path must startswith type_path_prefixes[type].

## Gates
user/role/type/range allowlists; HMAC+revoke; time; nonce allow-only.
