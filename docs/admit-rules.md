# ldapbindx admit rules

## Signing input
`v1|{kid}|{dn}|{filter}|{scope}|{attrs_csv}|{iat}|{nonce}`

## DN / filter
dn lowercase if required; dn ∈ allowed_bases; reject dn deny substrings.
filter must startswith filter_allow_prefixes; reject filter_deny_substrings.
scope allowlist; every attr ∈ attrs_allow; len(attrs)<=attrs_max; HMAC+revoke; time; nonce allow-only.
