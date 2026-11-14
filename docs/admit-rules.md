# ratchets admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{dh}|{pn}|{n}|{ciphertext_sha}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- n 相对接收链单调；重复 n replay
- 跳过消息数 ≤ max_skip
- DH 公钥在允许集或派生
- pn 绑定前链长度

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-next, ok-dh-step

Deny cases: bad-mac, replay, skip, dh, pn, gap, old, trunc

Reason codes should be stable snake_case identifiers matching the failing gate.
