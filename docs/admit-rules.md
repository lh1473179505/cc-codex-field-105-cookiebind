# kmswrap admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kek_kid}|{alg}|{aad_sha256}|{wrapped_sha256}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- alg 必须在 allowed_wrap_algs，禁止降级
- aad 原始字节哈希绑定
- kek_kid 在 epoch 内且未吊销
- wrapped 长度门禁

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-aes, ok-epoch-edge

Deny cases: bad-sig, alg-down, aad, epoch, revoked, short-wrap, pretty-aad, unknown-kid

Reason codes should be stable snake_case identifiers matching the failing gate.
