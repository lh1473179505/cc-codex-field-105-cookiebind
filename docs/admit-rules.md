# merkleinc admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{leaf_sha}|{root}|{path_csv}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- leaf 按规范字段序哈希，禁止 JSON pretty
- path 每步 L/R 方向必须正确重算到 root
- root 必须等于 policy.trusted_roots 之一
- kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-left, ok-mixed

Deny cases: bad-sig, pretty-leaf, path, root, revoked, empty-path, flip-dir, trunc

Reason codes should be stable snake_case identifiers matching the failing gate.
