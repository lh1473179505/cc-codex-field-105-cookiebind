# redteamx admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{payload_digest}`

`payload_digest` is the lowercase hex SHA-256 of the canonical JSON
(`sort_keys=True`, `separators=(",", ":")`, UTF-8) of the object's content
fields: every top-level field except `kid`, `sig`, and underscore-prefixed
metadata. The digest commits the signature to the payload attributes that the
classifier derives `primitives`, `obf_layers`, and `sample_class` from.
Underscore-prefixed fields such as `_sign_line` are untrusted hints and are
never used as the signing input.

HMAC-SHA256 over that line with the hex-decoded key secret, then base64url
without `=` padding.

## Interacting gates

- 危险原语命中则 high
- obf_layers 超过阈值升档
- research 例外需 kid 研究密钥且水印
- 生产路径拒绝 high

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-benign, ok-research

Deny cases: bad-sig, primitive, obf, prod-high, revoked, fake-research, empty, case

Reason codes should be stable snake_case identifiers matching the failing gate.
