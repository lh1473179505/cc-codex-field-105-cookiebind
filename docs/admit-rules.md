# airflowx admit rules

## Signing
`v1|{kid}|{dag_id}|{owner}|{pool}|{queue}|{iat}|{nonce}`

dag ∈ dags; owner/pool/queue ∈ lists; reject dag_deny_substrings; HMAC+revoke; time; nonce allow-only.
