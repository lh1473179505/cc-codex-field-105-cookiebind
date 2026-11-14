# seccompx admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{arch}|{default}|{syscalls_sha}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- arch 必须匹配
- defaultAction 只能 SCMP_ACT_ERRNO/SCMP_ACT_ALLOW 策略集
- syscall 参数约束按 index/op/value 检查
- kid 撤销；冲突规则 conflict

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-errno, ok-allowlist

Deny cases: bad-sig, arch, default, arg, conflict, revoked, unknown-call, empty

Reason codes should be stable snake_case identifiers matching the failing gate.
