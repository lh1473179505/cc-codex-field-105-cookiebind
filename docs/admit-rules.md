# pkceexch admit rules

## Signing
`v1|{kid}|{client_id}|{code_challenge}|{method}|{redirect}|{iat}|{nonce}`

client ∈ clients; redirect exact ∈ redirects; method ∈ methods; if forbid_plain method!=plain; len(challenge)==challenge_len; HMAC+revoke; time; nonce allow-only.
