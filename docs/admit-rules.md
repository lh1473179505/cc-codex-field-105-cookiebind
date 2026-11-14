# sbombind admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{doc_sha}|{comps_csv}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 每个组件 name@version 哈希必须命中 lock
- 许可证与允许集求交；禁止 copyleft_denied 列表
- excluded_paths 下的组件忽略；别名包按 alias_map 归一
- kid 撤销；缺组件 incomplete

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-full, ok-alias

Deny cases: bad-sig, hash, license, alias, incomplete, revoked, excluded-miss, case-name

Reason codes should be stable snake_case identifiers matching the failing gate.
