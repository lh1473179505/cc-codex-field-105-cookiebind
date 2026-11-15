# imgdigest admit rules

## Signing input
`v1|{kid}|{ref}|{digest}|{platform}|{cap_drop_csv}|{seccomp}|{iat}|{nonce}`

## Digest pin
ref must startswith allowed_repos; if forbid_mutable_tag_only: ref must contain `@` digest form and digest field must equal `sha256:`+hex after `@` OR digest field must match.
digest must startswith digest_prefix and 64-hex.

## Caps / seccomp
required_cap_drop ⊆ cap_drop; cap_drop ∩ forbidden_caps must be empty; seccomp ∈ allowed_seccomp.
platform allowlist; HMAC+revoke; time; nonce allow-only.
