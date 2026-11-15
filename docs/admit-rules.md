# scimfilt admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{filter_sha}|{depth}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 属性路径白名单
- 比较运算白名单
- 嵌套 depth≤max
- 拒绝注入括号逃逸；kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-eq, ok-and

Deny cases: bad-sig, attr, op, depth, inject, revoked, empty, case-attr

Reason codes should be stable snake_case identifiers matching the failing gate.

## Reason codes

- `policy_disabled` — policy.allowed is false
- `kid_unknown` — kid not present in keys
- `kid_revoked` — kid status is not active (denies even with valid HMAC)
- `bad_signature` — HMAC over the reconstructed sign line does not match, or the presented payload is not the signed one
- `filter_missing` — no filter payload could be resolved
- `empty_filter` — filter is empty/whitespace
- `injection_rejected` — parenthesis escape or string breakout attempt
- `filter_parse_error` — filter does not parse
- `attribute_not_allowed` — attribute path not in whitelist (case-sensitive; also covers case-attr)
- `operator_not_allowed` — comparison/logical operator not in whitelist
- `depth_exceeded` — nesting depth above policy max
- `replay_detected` — request id already present in the store

## Notes on this scaffold

- Signed content is the canonical JSON (`sort_keys`, `separators=(",", ":")`) of all request fields except the envelope fields `kid`, `sig`, `_sign_line`. The fixtures sign the 3-segment line `v1|{kid}|{filter_sha}` (no depth segment).
- The `marker` field names the abstract filter payload class; `scimfilt.engine` expands it to the concrete SCIM filter the gates evaluate. Library callers may pass a real `filter` string field instead.
