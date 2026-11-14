# oidcxch admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{client}|{code_sha}|{redirect}|{code_verifier}|{nonce}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- S256(code_verifier)==code_challenge
- redirect 精确（禁止前缀放宽）
- nonce 绑定 ID 段
- client 密钥；code 一次性 store

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-s256, ok-nonce

Deny cases: bad-pkce, redirect, nonce, client, replay-code, plain-pkce, query-extra, case-redir

Reason codes should be stable snake_case identifiers matching the failing gate.
