# wasmimp admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{imports_csv}|{mem_pages}|{export_start}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 每个 import module.func 在白名单
- mem_pages ≤ max
- 必须导出 _start 或 policy.entry
- kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-wasi, ok-tiny

Deny cases: bad-sig, import, mem, entry, revoked, dup-import, empty, case

Reason codes should be stable snake_case identifiers matching the failing gate.
