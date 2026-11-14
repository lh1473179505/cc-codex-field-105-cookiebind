# mtlsmap admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{fp}|{uri_san}|{role}|{not_after}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- fp 命中
- uri_san 匹配 spiffe-like 前缀策略
- role 授权
- 未过期；kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-pay, ok-ops

Deny cases: bad-sig, fp, uri, role, expired, revoked, case-uri, empty-role

Reason codes should be stable snake_case identifiers matching the failing gate.
