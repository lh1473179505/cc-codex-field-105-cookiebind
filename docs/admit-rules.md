# httpsigx admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`signature-base`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 覆盖字段集合必须包含要求项
- created/expires 窗
- keyid 目录与撤销
- @method/@path 绑定

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-get, ok-post

Deny cases: bad-sig, cover, created, expires, revoked, method, path, alg

Reason codes should be stable snake_case identifiers matching the failing gate.
