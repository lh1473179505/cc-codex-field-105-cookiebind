# mtlsbind admit rules

Offline mTLS-like client cert binding (JSON fixture, HMAC stands in for signature).

## Signing input

`v1|{kid}|{spiffe_id}|{sans_csv}|{eku_csv}|{iat}|{exp}|{nonce}`

## Gates

1. HMAC + kid_revoked.
2. SPIFFE trust domain in allowed_trust_domains (`spiffe://{td}/...`).
3. eku must intersect allowed_eku (fixture uses exact clientAuth).
4. At least one SAN ends with allowed_san_suffixes OR equals spiffe_id.
5. iat/exp within skew; max_age on iat.
6. nonce replay store; write only on allow.
