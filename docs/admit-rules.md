# vaultpath admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{path}|{caps_csv}|{not_paths_csv}|{exp}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 请求 path 必须在允许前缀下
- 命中 not_paths 则拒绝
- caps 不能超出令牌授予
- 时间窗与撤销；衰减后不可扩权

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-read, ok-write

Deny cases: bad-sig, prefix, not-path, cap, revoked, skew, widen, empty-cap

Reason codes should be stable snake_case identifiers matching the failing gate.
