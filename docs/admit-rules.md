# opaish admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{input_sha}|{rules_sha}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 按序求值 allow/deny；先匹配先生效
- 默认 deny
- 输入路径查询
- kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-allow, ok-second-rule

Deny cases: bad-sig, deny-rule, default, path, revoked, type, empty-rules, shadow

Reason codes should be stable snake_case identifiers matching the failing gate.

## Reason codes

- `invalid_type` — input is not an object or a required string field is missing/mistyped
- `unknown_kid` — kid is not present in the key store
- `kid_revoked` — kid exists but is not active
- `bad_signature` — HMAC does not match the signing input
- `replay_detected` — id was already admitted (present in the store)
- `deny_rule` — an explicit deny rule matched (first match wins)
- `default_deny` — no rule matched; default deny

Rules are evaluated in order (policy rules first, then the built-in
`/v1/{pkg}/` path allow rule); the first matching rule decides. When the
policy has no rules, the signing line omits `|{rules_sha}`. On allow the
object id is recorded in the store; deny and load failure never write it.
