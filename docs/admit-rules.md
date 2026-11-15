# yubikeyx admit rules

## Signing
`v1|{kid}|{public_id}|{session}|{use}|{iat}|{nonce}`

public_id ∈ ids and len==public_id_len; session >= session_min; use in [use_min,use_max]; HMAC+revoke; time; nonce allow-only. (Monotonicity vs store is part of admit: nonce store still required; session/use bounds from policy.)
