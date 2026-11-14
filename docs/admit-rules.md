# samlbind admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{issuer}|{audience}|{recipient}|{not_on_or_after}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- audience 精确
- recipient 匹配 ACS URL
- NotOnOrAfter 含 skew
- 签发者密钥与撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-sso, ok-skew

Deny cases: bad-sig, aud, recipient, expired, issuer, revoked, skew, empty-aud

Reason codes should be stable snake_case identifiers matching the failing gate.
