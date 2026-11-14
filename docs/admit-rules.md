# cosignoff admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{digest}|{identity}|{issuer}|{iat}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- digest 必须 sha256: 且匹配镜像
- identity 匹配 allow_identity_regex
- issuer 精确匹配
- 时间窗与 kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-ci, ok-release

Deny cases: bad-sig, digest, identity, issuer, revoked, skew, algo, tag-instead-digest

Reason codes should be stable snake_case identifiers matching the failing gate.
