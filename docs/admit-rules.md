# watermark admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{pos}|{mark_sha}|{score}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- pos 在允许嵌入点
- mark 对照密钥派生
- score ≥ threshold
- 篡改后 score 必降拒

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-img, ok-text

Deny cases: bad-sig, pos, mark, score, tamper, revoked, empty, wrong-key

Reason codes should be stable snake_case identifiers matching the failing gate.
