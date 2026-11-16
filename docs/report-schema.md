# report
```json
{"decision":"allow|deny","reason_codes":[],"sub":""}
```

## reason_codes
- `malformed_token`: token 缺字段或字段类型不对，无法重建签名输入。
- `unknown_kid` / `malformed_key`: kid 不在密钥表，或密钥 secret 不是合法 hex。
- `bad_signature`: HMAC-SHA256 签名与 `v1|...` 签名输入不一致（常数字节比较）。
- `kid_revoked`: 命中密钥的 `status` 不是 `active`。
- `iss_not_allowed`: iss 不在 `allowed_issuers`。
- `aud_not_allowed`: aud 中存在不在 `allowed_audiences` 的条目。
- `azp_not_allowed` / `azp_not_in_aud`: azp 不在 `allowed_azp`，或 azp 不是 aud 成员。
- `acr_not_satisfied`: acr 不在 `required_acr`。
- `token_expired` / `auth_time_in_future`: 超过 `clock_skew_seconds` 容忍窗。
- `nonce_replayed`: nonce 已存在于 store（allow-only，放行时才写入）。
