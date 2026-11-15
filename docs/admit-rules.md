# edgechaln admit rules

Edge challenge ticket. Signature binds raw_path + canonical query + headers + origin + body.

## Signing input
`v1|{kid}|{method}|{host}|{raw_path}|{canon_query}|{headers_csv}|{origin}|{content_type}|{body_sha256}|{iat}|{exp}|{nonce}`

`canon_query`: parse_qsl keep blanks, sort by (key,value), urlencode.

## Path normalization (must apply BEFORE allow/deny prefix checks)
1. Reject if raw_path contains `%2e` / `%2E` / `..` / `//` / `\\` (encoded or not) => `path_unsafe`.
2. Then check path_allow_prefixes / path_deny_prefixes on the raw_path string as given only if step1 passed.
   (Fixtures encode attacks in raw_path; do not URL-decode into existence of allow — reject unsafe encodings first.)

## Other gates
3. HMAC + kid_revoked.
4. host/method allowlists.
5. if strict_query: every query key ∈ allowed_query_keys.
6. required_headers present (case-insensitive names); denied_headers absent.
7. if credentials_mode and require_origin_for_credentials: origin exact ∈ allowed_origins.
8. POST: content_type ∈ allowed_content_types; body_sha256 64-hex.
9. time window + nonce store; write only on allow.

## Compatibility
- inspect remains field echo only.
- deny must not write store.
