# webauthn admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{cred_id}|{rp_id_hash}|{flags}|{sign_count}|{client_hash}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- rpIdHash 匹配
- flags 要求 UP；require_uv 时 UV
- sign_count 严格大于 stored；相等 replay
- clientData 类型 webauthn.get 且 challenge 绑定

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-uv, ok-up-only

Deny cases: bad-sig, rp, up, uv, replay-count, challenge, type, cred

Reason codes should be stable snake_case identifiers matching the failing gate.
