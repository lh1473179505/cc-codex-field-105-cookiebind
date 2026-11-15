# cargoaud admit rules

## Signing
`v1|{kid}|{name}|{version}|{advisory}|{severity}|{yanked}|{iat}|{nonce}`

name ∈ crates; version ∈ versions; severity_rank[severity] <= severity_rank[max_severity]; if forbid_yanked and yanked==1 deny; HMAC+revoke; time; nonce allow-only.
