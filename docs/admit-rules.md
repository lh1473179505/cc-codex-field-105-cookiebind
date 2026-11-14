# fileinteg admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{root}|{entries_sha}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 非允许集路径哈希必须匹配基线
- 允许变更集可不同
- 拒绝符号链接逃出 root
- xattr 绑定可选

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-clean, ok-allowed-edit

Deny cases: bad-sig, hash, symlink, extra-file, revoked, xattr, case-path, missing

Reason codes should be stable snake_case identifiers matching the failing gate.
