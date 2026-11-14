# samlgate admit rules

## Signing input
`v1|{kid}|{issuer}|{audience}|{recipient}|{subject}|{not_before}|{not_on_or_after}|{nonce}`

## Gates
1. HMAC + kid_revoked.
2. issuer/audience/recipient exact allowlists.
3. not_before <= now+skew; now < not_on_or_after (+skew rules).
4. nonce store allow-only.
