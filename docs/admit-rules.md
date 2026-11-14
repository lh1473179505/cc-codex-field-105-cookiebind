# oidcbind admit rules

## Signing input
`v1|{kid}|{iss}|{aud_csv}|{azp}|{sub}|{acr}|{auth_time}|{exp}|{nonce}`

## Gates
1. HMAC + kid_revoked.
2. iss exact allowlist.
3. every aud must be in allowed_audiences; azp in allowed_azp; azp must appear in aud.
4. acr must be in required_acr.
5. auth_time/exp skew; nonce store allow-only.
