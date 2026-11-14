# spiffejwt admit rules

## Signing input
`v1|{kid}|{td}|{sub}|{aud_csv}|{iat}|{exp}|{nonce}`

## Gates
1. HMAC + kid_revoked.
2. td allowlist; every aud in allowed_aud.
3. if sub_must_match_td: sub starts with `spiffe://{td}/`.
4. iat/exp skew; nonce store allow-only.
