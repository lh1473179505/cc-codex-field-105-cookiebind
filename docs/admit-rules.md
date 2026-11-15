# jwksrot admit rules

## Signing
`v1|{kid}|{issuer}|{kid_new}|{kid_old}|{overlap}|{alg}|{iat}|{nonce}`

## Gates
issuer allowlist; alg allowlist; if forbid_same_kid and kid_new==kid_old deny; overlap in [min,max]; HMAC+revoke; time; nonce allow-only.
