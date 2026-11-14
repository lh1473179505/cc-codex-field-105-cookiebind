# scimfilt admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{filter_sha}|{depth}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 属性路径白名单
- 比较运算白名单
- 嵌套 depth≤max
- 拒绝注入括号逃逸；kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-eq, ok-and

Deny cases: bad-sig, attr, op, depth, inject, revoked, empty, case-attr

Reason codes should be stable snake_case identifiers matching the failing gate.
