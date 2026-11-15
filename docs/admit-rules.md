# esqueryx admit rules

## Signing
`v1|{kid}|{index}|{user}|{qtype}|{fields}|{iat}|{nonce}`

index must equal one of indices OR match prefix pattern ending with `*` (literal prefix before *); fields csv ⊆ field_allow; qtype ∈ qtypes and not forbid; reject index_deny_substrings; HMAC+revoke; time; nonce allow-only.
