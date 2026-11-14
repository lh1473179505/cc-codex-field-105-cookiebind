# cosignoff admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{digest}|{identity}|{issuer}|{iat}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Input object fields

- `image`: digest of the image being admitted, e.g. `sha256:<64 hex>`
- `kid`: key id, must exist in `keys.keys`
- `digest`: digest claimed by the attestation (signed)
- `identity`: signer identity (signed)
- `issuer`: token issuer (signed)
- `iat`: unix timestamp, integer (signed)
- `sig`: base64url-unpadded HMAC-SHA256 over the sign line

The sign line is reconstructed from the signed fields; `_sign_line`, if
present, is informational only and never trusted.

## Policy fields

- `issuer`: required exact issuer string
- `allow_identity_regex`: regex the identity must match
- `clock_skew_seconds`: allowed future skew for `iat`
- `max_age_seconds`: maximum age of `iat`
- `allowed`: optional kill switch; `false` denies everything

## Interacting gates

- digest 必须 sha256: 且匹配镜像
- identity 匹配 allow_identity_regex
- issuer 精确匹配
- 时间窗与 kid 撤销

## Reason codes

- `signature_invalid`: HMAC does not match the reconstructed sign line
- `kid_unknown`: kid not present in keys
- `kid_revoked`: key status is not `active`, even if the signature verifies
- `digest_algorithm`: signed digest is not `sha256:<64 hex>` (includes tags)
- `digest_mismatch`: signed digest does not equal `image`
- `identity_not_allowed`: identity does not match `allow_identity_regex`
- `issuer_mismatch`: issuer differs from `policy.issuer`
- `iat_out_of_window`: `iat` is newer than `now + clock_skew_seconds` or
  older than `now - max_age_seconds`
- `replay`: signature already recorded in the store
- `policy_disabled`: `policy.allowed` is `false`

All applicable codes are reported in the order above; `decision` is `deny`
if the list is non-empty. Only `allow` writes the signature to the store
(`items[sig] = {"ts": iat}`) for replay protection.

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-ci, ok-release

Deny cases: bad-sig, digest, identity, issuer, revoked, skew, algo, tag-instead-digest

Reason codes should be stable snake_case identifiers matching the failing gate.
