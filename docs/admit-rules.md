# graphqlx admit rules

## Signing
`v1|{kid}|{operation}|{depth}|{complexity}|{fields}|{iat}|{nonce}`

operation ∈ operations; depth<=depth_max; complexity<=complexity_max; every field ∈ field_allow and not in forbid_fields; HMAC+revoke; time; nonce allow-only.
