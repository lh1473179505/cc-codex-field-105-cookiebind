# smimearc admit rules

## Signing
`v1|{kid}|{from_addr}|{to_addr}|{arc_i}|{cv}|{iat}|{nonce}`

Domain part after @ must ∈ from_domains/to_domains; arc_i in [0,arc_i_max]; cv ∈ cv_allow; if forbid_cv_fail and cv==fail deny; HMAC+revoke; time; nonce allow-only.
