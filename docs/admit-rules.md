# gitgpgx admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{tree}|{parents_csv}|{trailer_sha}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- kid 在 trust_store 且 level>=policy.min_trust
- tree 哈希绑定；parents 集合匹配
- 必需 trailer 键值
- 吊销与过期

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-main, ok-merge

Deny cases: bad-sig, trust, tree, trailer, revoked, parent, expired, extra-parent

Reason codes should be stable snake_case identifiers matching the failing gate.
