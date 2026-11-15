# agentfwd admit rules

## Signing input
`v1|{kid}|{fp}|{dst}|{constraint}|{lifetime}|{iat}|{nonce}`

## Bind
fp ∈ fps; dst endswith one of fps[fp].dst_suffixes; constraint ∈ fps[fp].constraints;
reject dst deny substrings; lifetime in [min,max]; HMAC+revoke; time; nonce allow-only.
