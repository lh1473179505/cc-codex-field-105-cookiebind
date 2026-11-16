# purlseal admit rules

## Signing input
`v1|{kid}|{purl}|{registry}|{name}|{version}|{digest}|{license}|{iat}|{nonce}`

## PURL binding
purl must start with one of allowed_types; name/version must appear in purl (`/{name}@{version}`).
If forbid_uppercase_in_purl / require_lowercase_name: the name and the whole purl must be lowercase.

## Gates
registry/license allowlists; denied_names; digest must use digest_alg prefix and 64-hex; HMAC+revoke; time; nonce allow-only.

## HMAC
Canonical input is the 10-field `v1|...` line above, joined with `|` and encoded UTF-8.
The key `secret` is hex-decoded; the MAC is HMAC-SHA256, emitted as base64url without padding.
Verification uses constant-time comparison. Only keys with `status: active` may verify.

## Decision
Every gate is evaluated; the report carries all failing reason codes. The package is
`allow` only when no code fired. On allow the nonce is recorded in the store as
`items[nonce] = {"ts": now_unix}`; on deny the store is never written.

Reason codes:

- `malformed_input`: required field missing, wrong type, or non-integer `iat`
- `bad_purl_type`: purl does not begin with an `allowed_types` entry plus `/`
- `purl_binding_mismatch`: `/{name}@{version}` does not occur in the purl
- `uppercase_name`: `name` is not lowercase or the purl contains uppercase letters
- `registry_not_allowed`: registry outside `allowed_registries`
- `name_denied`: name listed in `denied_names`
- `license_not_allowed`: license outside `allowed_licenses`
- `bad_digest`: not `{digest_alg}:64 lowercase hex chars`
- `unknown_kid` / `key_revoked`: signing key missing or not active
- `bad_signature`: HMAC does not match
- `iat_out_of_window`: `iat > now + clock_skew_seconds` or `iat < now - max_age_seconds`
- `nonce_replayed`: nonce already present in the store (allow-only semantics)
