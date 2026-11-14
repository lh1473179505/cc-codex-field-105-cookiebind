# trustroll admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{old_kid}|{new_kid}|{overlap_start}|{overlap_end}|{evidence_sha}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- now 必须落在重叠窗
- evidence 由 old 签 new
- 紧急吊销表优先
- 禁止跳过重叠

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-roll, ok-edge

Deny cases: bad-sig, overlap, evidence, emergency, unknown-old, unknown-new, skew, gap

Reason codes should be stable snake_case identifiers matching the failing gate.
