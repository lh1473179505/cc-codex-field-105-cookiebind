# kmswrap admit rules

## Input object fields

- `id`, `kid`, `alg`, `sig`: strings
- `aad_b64`, `wrapped_b64`: base64 of the raw bytes
- `aad_sha256`, `wrapped_sha256`: lowercase hex SHA-256 of the raw bytes

The aad hash binds the raw bytes exactly as transported; re-serializing or
canonicalizing the aad before hashing is a violation.

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kek_kid}|{alg}|{aad_sha256}|{wrapped_sha256}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- alg 必须在 allowed_wrap_algs，禁止降级
- aad 原始字节哈希绑定
- kek_kid 在 epoch 内且未吊销
- wrapped 长度门禁

Key epochs come from `keys.json` (`not_before`/`not_after`, ISO-8601 or unix)
and are checked against `now` with `policy.clock_skew_seconds` of leeway on
both ends (inclusive). `policy.allowed_wrap_algs` lists the permitted `alg`
values; `policy.min_wrapped_bytes` is the minimum wrapped length in bytes.

## Reason codes

- `alg_not_allowed`
- `aad_sha256_mismatch`
- `wrapped_sha256_mismatch`
- `wrapped_too_short`
- `unknown_kid`
- `key_revoked`
- `key_outside_epoch`
- `bad_signature`

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-aes, ok-epoch-edge

Deny cases: bad-sig, alg-down, aad, epoch, revoked, short-wrap, pretty-aad, unknown-kid

Reason codes should be stable snake_case identifiers matching the failing gate.
