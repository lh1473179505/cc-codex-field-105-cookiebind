# opaish admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{input_sha}|{rules_sha}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 按序求值 allow/deny；先匹配先生效
- 默认 deny
- 输入路径查询
- kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-allow, ok-second-rule

Deny cases: bad-sig, deny-rule, default, path, revoked, type, empty-rules, shadow

Reason codes should be stable snake_case identifiers matching the failing gate.
