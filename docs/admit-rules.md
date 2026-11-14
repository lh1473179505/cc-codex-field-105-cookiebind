# dpopbind admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`base64url(header).base64url(payload)`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- htm/htu 精确匹配请求
- jti 防重放 store
- access token 存在时 ath=base64url(sha256(token))
- iat 窗；密钥 jwk 指纹

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-get, ok-ath

Deny cases: bad-sig, htm, htu, jti, ath, iat, jwk, alg

Reason codes should be stable snake_case identifiers matching the failing gate.
