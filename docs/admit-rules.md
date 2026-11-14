# jwtcrit admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`base64url(header).base64url(payload)`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- alg=HS256；crit 列出的头必须理解且通过
- 拒绝 jku/x5u；typ 规范化后必须 JWT
- kid 不得含 /..\ 路径穿越；撤销表
- iss/aud/exp 策略

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-plain, ok-crit-ok

Deny cases: bad-sig, crit, jku, typ, kid-path, revoked, aud, exp

Reason codes should be stable snake_case identifiers matching the failing gate.
