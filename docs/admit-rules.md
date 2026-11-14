# jarseal admit rules

Offline signed archive (JAR-like). HMAC over CODE.SF line; entry digests bind path+bytes.

## Signing input (UTF-8)

`v1|{kid}|{main_class}|{path=sha256,...}|{created}|{nonce}`

Entry digests appear in **array order**. Each entry `sha256` is
`SHA256(utf8(path) || 0x00 || content_bytes)` hex. Separately, `body_sha256[path]`
is `SHA256(content_bytes)` only — used when `require_body_sha_match` to catch
fixtures that keep entry digests but swap body map.

## Gates

1. Verify HMAC with kid; revoked kid => `kid_revoked` even if HMAC ok.
2. `main_class` exact allowlist.
3. Every entry path: no absolute; no forbidden substrings (`../`); must start with an allowed prefix.
4. Entry count <= max_entries.
5. If require_body_sha_match: every entry path present in body_sha256; recompute entry digest consistency is the implementer's duty against provided maps (fixtures are consistent except deny-body-mismatch where body map disagrees with what entry digests imply — treat mismatched body as `body_mismatch` when policy requires body map integrity vs entry list presence).
   Practical rule for fixtures: for each path, if body_sha256[path] is present, the pair (path, body) must be able to reproduce entries[].sha256; else `body_mismatch`.
6. `created` within skew of now (not older than skew window beyond policy — use `now - created <= 300` or clock_skew*2; fixtures: deny-stale is 1 day old => `stale`).
7. Nonce store: existing => `replay`; write only on allow.

## Exit
allow=0 deny=1 loadfail=2
