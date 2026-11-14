# saslscram admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{user}|{nonce}|{channel}|{proof_sha}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- nonce 必须以前缀 server_nonce 开头
- channel binding 类型与数据匹配
- proof 对照 stored key
- 用户存在且未禁用

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-plain, ok-cbind

Deny cases: bad-proof, nonce, channel, user, disabled, iter, salt, cbind-flag

Reason codes should be stable snake_case identifiers matching the failing gate.
