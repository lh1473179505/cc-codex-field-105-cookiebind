# sandtrap admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{trace_sha}|{required_csv}|{denied_csv}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- required 全部出现且顺序约束
- denied 任一出现则拒
- 参数字面量匹配
- kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-openread, ok-connect

Deny cases: bad-sig, missing-req, denied-call, arg, order, revoked, extra, empty

Reason codes should be stable snake_case identifiers matching the failing gate.
