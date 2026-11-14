# agewrap admit rules

## Signing input
`v1|{kid}|{recipient}|{alg}|{aad}|{ct_hash}|{iat}|{nonce}`

## Gates
1. HMAC + kid_revoked.
2. recipient allowlist; alg allowlist; alg not in deny_alg_downgrade.
3. aad must start with one required_aad_prefixes.
4. iat age + nonce store allow-only.
