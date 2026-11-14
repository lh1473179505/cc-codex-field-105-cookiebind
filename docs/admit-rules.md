# idsrule admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{sid}|{msg}|{content_sha}|{offset}|{depth}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- content 在 offset/depth 窗口命中；nocase 按规则
- 更高 priority 的 sid 覆盖
- flow 边界 established 要求
- 规则签名 kid

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-hit, ok-nocase

Deny cases: bad-sig, miss, offset, priority, flow, revoked, depth, case

Reason codes should be stable snake_case identifiers matching the failing gate.
