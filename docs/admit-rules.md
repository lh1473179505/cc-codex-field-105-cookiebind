# agegatex admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{jurisdiction}|{birth_hash}|{threshold}|{nonce}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- birth_hash 匹配证明
- 年龄 ≥ threshold
- jurisdiction 策略
- nonce 防重放；kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-us, ok-eu

Deny cases: bad-sig, hash, underage, jurisdiction, replay, revoked, skew, threshold

Reason codes should be stable snake_case identifiers matching the failing gate.
