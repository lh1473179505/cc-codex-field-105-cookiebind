# fuzzcrash admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{stack_norm_sha}|{fault}|{severity}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 栈帧地址剥离 ASLR 后哈希
- fault 类型门禁
- severity 不得低于策略
- 去重 store

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-segv, ok-abrt

Deny cases: bad-sig, stack, fault, sev, dup, revoked, trunc-stack, raw-addr

Reason codes should be stable snake_case identifiers matching the failing gate.
