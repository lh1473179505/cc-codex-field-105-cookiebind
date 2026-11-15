# gosumpin admit rules

## Signing
`v1|{kid}|{module}|{version}|{hash}|{algo}|{iat}|{nonce}`

module ∈ modules; version startswith version_prefixes; algo ∈ algos and not forbid; len(hash)==hash_len; HMAC+revoke; time; nonce allow-only.
