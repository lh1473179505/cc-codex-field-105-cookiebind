# canarytok admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{token_id}|{channel}|{env}|{ts}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- channel 在允许集
- env 绑定；跨环境拒绝
- token_id 去重 store；仅首次 allow 写入
- 时间窗与撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-dns, ok-http

Deny cases: bad-sig, channel, env, replay, revoked, skew, unknown-token, case-env

Reason codes should be stable snake_case identifiers matching the failing gate.
