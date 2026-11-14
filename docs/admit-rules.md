# dkimarc admit rules

## Signing input
`v1|{kid}|{d}|{s}|{from_domain}|{arc_cv}|{body_hash}|{iat}|{nonce}`

## Gates
1. HMAC + kid_revoked.
2. d/s allowlists.
3. if from_must_align_d: from_domain == d.
4. arc_cv in required_arc_cv.
5. iat age + nonce store allow-only.
