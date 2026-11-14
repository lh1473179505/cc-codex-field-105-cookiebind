# sealedbox admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{recipient_kid}|{epoch}|{aad_sha}|{cipher_sha}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- recipient 必须 active
- epoch 匹配密钥纪元
- aad 绑定；失败统一 bad_unseal（不区分密钥错误）
- 密文长度门禁

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-msg, ok-aad

Deny cases: bad-unseal, epoch, aad, revoked, short, wrong-recipient, pretty-aad, future-epoch

Reason codes should be stable snake_case identifiers matching the failing gate.
