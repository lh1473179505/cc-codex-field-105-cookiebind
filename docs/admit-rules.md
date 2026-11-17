# symfetch admit rules

`symbol_server` must match `server_pattern` and exactly select `servers[symbol_server]`; HTTP, trailing-slash variants and unknown hosts are invalid. Traverse `builds[build_id].files[file_name]`, then require `arch` in that file's `arches`. `file_name` is one basename containing none of `file_deny_substrings`.

`file_sha256` is exactly `sha256_hex_len` lowercase hexadecimal characters and must equal the selected file entry's `sha256`. Matching digest syntax alone does not authorize a different build or file.

`path` must contain none of `path_deny_substrings` and must exactly equal `/{build_id}/{arch}/{file_name}` using the unmodified input fields. Do not decode, normalize, reorder or clean an unsafe path into this canonical form. Component count is therefore exactly three after the leading slash.

The signature covers server, build, file, architecture, digest and path. Require active-key HMAC and fresh iat under age/skew limits; consume nonce and save store only after allow.

## Signed contract

The HMAC message is the exact pipe-joined string built from the unmodified token fields:

```
v1|{kid}|{symbol_server}|{build_id}|{file_name}|{arch}|{file_sha256}|{path}|{iat}|{nonce}
```

`iat` is rendered in decimal; every other component is the original string. The key `secret` is hex-decoded to bytes, the MAC is HMAC-SHA256, and `sig` is the base64url encoding without `=` padding. Comparison uses a constant-time check. A key whose `status` is not `active` is rejected before signature verification.

## Freshness and replay

A token is fresh only when `iat - clock_skew_seconds <= now <= iat + max_age_seconds + clock_skew_seconds`. A seen `nonce` (present in `store["items"]`) is rejected as a replay. The nonce is inserted with `{"ts": now}` only after every gate, including the freshness check, passes; any deny leaves the store byte-for-byte unchanged and no store file is written.

## Gate order and reason codes

Each failed gate produces exactly one `reason_codes` entry and stops evaluation:

1. `malformed_symbol`, `missing_field`, `malformed_field`, `malformed_iat` for shape/type errors.
2. `server_denied`, `build_denied`, `file_denied`, `arch_denied` for service-directory traversal.
3. `digest_format` (lowercase-hex shape) and `digest_binding` (exact match to the selected file entry).
4. `path_denied` for any unsafe or non-canonical path.
5. `unknown_kid`, `key_revoked`, `bad_sig` for key and HMAC verification.
6. `iat_expired` for freshness failures and `nonce_replay` for replays.

An allow report has an empty `reason_codes` list. `inspect` only projects token fields and never reads keys, policy or the store.
