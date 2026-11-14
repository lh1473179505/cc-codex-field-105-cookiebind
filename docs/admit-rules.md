# rlsrow admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{tenant}|{roles_csv}|{pred_sha}`

HMAC-SHA256 over that line, then base64url without `=` padding.

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
