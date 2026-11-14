# yaragate admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{rule}|{strings_sha}|{cond}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 所有 strings 按修饰符匹配
- cond 布尔（and/or/not）求值
- 文件大小门禁
- kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-and, ok-or

Deny cases: bad-sig, string, cond, size, revoked, hex, wide, empty

Reason codes should be stable snake_case identifiers matching the failing gate.
