# auditmatch admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{key}|{exe}|{success}|{uid}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- key 精确
- exe 规范化实路径必须匹配
- success 布尔与规则一致
- uid 范围；kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-fail, ok-ok

Deny cases: bad-sig, key, exe, success, uid, revoked, rel-exe, case-key

Reason codes should be stable snake_case identifiers matching the failing gate.
