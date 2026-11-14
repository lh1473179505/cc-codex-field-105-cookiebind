# sfkeyx admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`sf-dict-canonical`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 字典键排序
- 参数序与类型标记
- 签名对照
- kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-dict, ok-params

Deny cases: bad-sig, order, type, param, revoked, dup-key, float, empty

Reason codes should be stable snake_case identifiers matching the failing gate.
