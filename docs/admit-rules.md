# selctx admit rules

## Signing input
`v1|{kid}|{user}|{role}|{type}|{range}|{path}|{iat}|{nonce}`

## Path
Reject deny substrings; path must startswith type_path_prefixes[type].

## Gates
user/role/type/range allowlists; HMAC+revoke; time; nonce allow-only.

## Gate order
The first failed gate decides the single `reason_codes` entry:

1. `malformed` — missing/empty string fields or non-integer `iat`
2. `path_traversal` — any `path_deny_substrings` entry found in `path`
3. `type_denied` — `type` not in `allowed_types`
4. `path_denied` — `path` matches no prefix in `type_path_prefixes[type]`
5. `user_denied` / `role_denied` / `range_denied` — allowlist checks
6. `unknown_kid` — `kid` absent from `keys` (or its secret is not hex)
7. `bad_signature` — HMAC-SHA256 over the signing input, base64url no padding, compared in constant time
8. `key_revoked` — key status is not `active`
9. `iat_future` / `iat_expired` — outside `clock_skew_seconds` / `max_age_seconds`
10. `nonce_replay` — nonce already present in the store

Path traversal is always evaluated before the type/prefix binding so a
`..`-laden path can never be admitted by a matching prefix. A deny never
mutates the store; on allow the nonce is recorded as
`items[nonce] = {"ts": iat}`.
