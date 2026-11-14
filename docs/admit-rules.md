# honeytok admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{fp}|{src}|{severity}|{ts}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- fp 命中蜜标库
- src 不在 prod_exclusions
- severity 映射告警级别
- kid 与时间窗

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-ssh, ok-aws

Deny cases: bad-sig, fp, prod, severity, revoked, skew, unknown-fp, case

Reason codes should be stable snake_case identifiers matching the failing gate.
