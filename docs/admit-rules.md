# ratebnd admit rules

## Signing
`v1|{kid}|{bucket}|{subject}|{cost}|{window}|{burst}|{iat}|{nonce}`

## Gates
bucket ∈ buckets; subject startswith subjects_prefix; cost in (0,cost_max] (forbid negative); window ∈ windows; burst <= burst_max; HMAC+revoke; time; nonce allow-only.
