# pasetox admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v4.local|{kid}|{payload_sha}|{footer_sha}|{implicit_sha}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 版本必须 v4.local
- footer 绑定策略租户；implicit assertion 必须匹配请求上下文
- kid 版本与撤销
- payload 声明 aud/sub 受策略约束

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-basic, ok-footer

Deny cases: bad-sig, ver, footer, implicit, aud, revoked, kid-ver, payload

Reason codes should be stable snake_case identifiers matching the failing gate.
