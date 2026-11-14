# cookiebind admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{name}|{prefix}|{samesite}|{csrf}|{path}|{iat}|{exp}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- name 必须以 `__Host-` 或 `__Secure-` 前缀策略要求的形式出现；`__Host-` 时 path 必须是 `/` 且不能带 Domain
- samesite 落在 policy.allowed_samesite；凭证模式 require_csrf 时 csrf 必须等于 HMAC(body_csrf_seed)
- path 既要避开 denied_path_substrings，又要命中 path_allow（exact/prefix）
- kid 撤销即使 HMAC 正确也是 kid_revoked；只有 allow 才写 jti 防重放
- |now-iat|/exp 受 clock_skew 约束

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-host, ok-secure

Deny cases: bad-sig, host-path, samesite, csrf, path, revoked, replay, skew

Reason codes should be stable snake_case identifiers matching the failing gate.
