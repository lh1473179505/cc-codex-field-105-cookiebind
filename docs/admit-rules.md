# npmotp admit rules

## Signing
`v1|{kid}|{pkg}|{otp}|{user}|{registry}|{iat}|{nonce}`

pkg scope is substring before `/` (e.g. @pay); scope ∈ scopes; user/registry allow; otp length and digits-only; reject pkg deny substrings; HMAC+revoke; time; nonce allow-only.
