# vaultcap admit rules

## Signing input
`v1|{kid}|{ns}|{path}|{caps_csv}|{wrap_ttl}|{iat}|{nonce}`

## Path safety
Reject path containing deny substrings. ns ∈ allowed_namespaces; path must startswith one of path_allow_prefixes[ns].

## Caps
Every cap ∈ caps_allow; set(caps) ⊆ set(caps_max); if forbid_sudo and 'sudo' in caps => deny.
wrap_ttl <= wrap_ttl_max; HMAC+revoke; time; nonce allow-only.
