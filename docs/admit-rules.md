# rlsrow admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{tenant}|{roles_csv}|{pred_sha}`

HMAC-SHA256 over that line, then base64url without `=` padding.

In this scaffold the `{tenant}|{roles_csv}|{pred_sha}` tuple is committed as a
single digest field: the commitment is the SHA-256 hex of the canonical claims
JSON (all object fields except `sig` and underscore-prefixed transport hints,
`sort_keys=True`, compact separators). The wire signing line is therefore
`v1|{kid}|{commitment}`; a `_sign_line` hint, when present, must equal the
recomputed canonical line.

## Interacting gates

- tenant 绑定
- roles 求交
- 谓词不得用 OR 扩到其他 tenant
- kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-owner, ok-shared

Deny cases: bad-sig, tenant, role, or-escalation, revoked, empty-pred, shared-miss, case

Reason codes should be stable snake_case identifiers matching the failing gate.

## Reason codes

- `malformed_object` — missing required signed fields
- `kid_unknown` — kid not in the key ring
- `kid_revoked` — kid status is not `active`
- `bad_signature` — HMAC or commitment mismatch, or invalid predicate attestation
- `tenant_mismatch` — predicate not bound to the row tenant (case-sensitive)
- `role_mismatch` — predicate roles do not intersect the granted roles
- `or_escalation` — predicate OR spans more than one tenant
- `empty_predicate` — predicate has no tenant binding and no role requirement
- `unknown_predicate` — predicate token outside the policy vocabulary
- `already_admitted` — object id already present in the store
