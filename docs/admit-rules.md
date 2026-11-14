# redteamx admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{primitives_csv}|{obf_layers}|{sample_class}`

HMAC-SHA256 over that line, then base64url without `=` padding.

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
