# s3presign admit rules

## Signing
`v1|{kid}|{bucket}|{key}|{method}|{expires}|{iat}|{nonce}`

bucket ∈ buckets; key startswith key_prefixes; reject deny substrings; method allow; expires <= expires_max; HMAC+revoke; time; nonce allow-only.
