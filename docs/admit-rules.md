# relreqx admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{origin}|{referer}|{mode}|{dest}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- same-site 判定按 schemeful
- mode cors/navigate 规则不同
- dest 绑定
- kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-same, ok-cors

Deny cases: bad-sig, site, mode, dest, revoked, null-origin, http-downgrade, case-host

Reason codes should be stable snake_case identifiers matching the failing gate.
