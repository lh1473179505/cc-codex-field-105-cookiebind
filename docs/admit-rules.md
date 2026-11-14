# canarytok admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{token_id}|{channel}|{env}|{ts}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Input object

The admit input is a JSON object with string fields `kid`, `token_id`,
`channel`, `env`, `sig` and integer field `ts` (unix seconds). The
signature is recomputed over the canonical line built from these fields;
any attacker-supplied precomputed line is ignored.

Policy supplies `allowed_channels` (list), `env` (binding, case-sensitive),
`clock_skew_seconds`, and `known_token_ids`.

## Interacting gates

- channel 在允许集
- env 绑定；跨环境拒绝
- token_id 去重 store；仅首次 allow 写入
- 时间窗与撤销

All gates are evaluated and every failing gate contributes a reason code:

- `invalid_input` — required fields missing or of the wrong type
- `unknown_key` — kid not present in keys
- `key_revoked` — key status is not `active`
- `bad_signature` — HMAC over the canonical line does not match `sig`
- `unknown_token` — token_id not in policy `known_token_ids`
- `channel_not_allowed` — channel not in policy `allowed_channels`
- `env_mismatch` — env differs from the policy binding
- `token_replayed` — token_id already in the store
- `timestamp_out_of_window` — |now - ts| exceeds `clock_skew_seconds`

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-dns, ok-http

Deny cases: bad-sig, channel, env, replay, revoked, skew, unknown-token, case-env

Reason codes should be stable snake_case identifiers matching the failing gate.
