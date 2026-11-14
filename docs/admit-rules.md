# mailarc admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{i}|{cv}|{ams_sha}|{avs_sha}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 实例 i 严格递增从 1
- cv 传递：首跳 pass/none 规则按文档，中间 fail 则整链 fail
- ams/avs 哈希绑定对应头集
- kid DNS 轮换表与撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-single, ok-chain

Deny cases: bad-sig, order, cv, ams, avs, revoked, gap-i, dup-i

Reason codes should be stable snake_case identifiers matching the failing gate.
