# torhsauth admit rules

## Signing input
`v1|{kid}|{onion}|{client}|{revision}|{iat}|{nonce}`

## Gates
1. HMAC + kid_revoked.
2. onion/client allowlists.
3. revision >= min_revision.
4. iat age + nonce store allow-only.
