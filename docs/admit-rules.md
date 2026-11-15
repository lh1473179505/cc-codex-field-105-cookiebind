# hstsbind admit rules

## Signing
`v1|{kid}|{host}|{max_age}|{include_sub}|{preload}|{iat}|{nonce}`

host ∈ hosts; max_age >= max_age_min; if require_sub then include_sub must be 1; if not allow_preload then preload must be 0; if forbid_preload_without_sub and preload and not include_sub => deny; HMAC+revoke; time; nonce allow-only.
