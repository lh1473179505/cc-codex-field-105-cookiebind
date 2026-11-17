# jailparam admit rules

## Signing input

The complete signed line (ASCII) is:

`v1|{kid}|{name}|{jid}|{hostname}|{ip4}|{path}|{securelevel}|{iat}|{nonce}`

HMAC-SHA256 over that line with the hex-decoded key secret, then base64url
without `=` padding. The engine always recomputes the line from the request
itself; a supplied signature is never trusted. Every field participates, so
tampering any field breaks verification.

## Gates

Gates are evaluated in this order; the first failure is the single reason
code in the report.

1. name syntax: at most `name_max_len` characters and matching
   `[a-z][a-z0-9_-]*`, checked before any policy lookup -> `name_syntax`
2. jail selection: `policy.jails[name]` must exist -> `name_unknown`
3. jid: an integer (booleans rejected), within `jid_min`/`jid_max` ->
   `jid_range`, then exactly equal to the selected jail's jid ->
   `jid_binding`
4. hostname: an exact lowercase DNS name equal to the jail hostname ->
   `hostname`
5. ip4: parse as a plain IPv4 address with no prefix or zone -> `ip4_syntax`;
   reject `forbidden_ip4`, multicast and loopback addresses (along with
   unspecified, reserved and link-local specials) -> `ip4_forbidden`; then
   require numeric membership in one of the jail's `ip4_networks` (address
   math, never string prefixes) -> `ip4_network`
6. path: absolute canonical path without `path_deny_substrings` or
   empty/`.`/`..` components; traversal is rejected as written and never
   normalized away -> `path_traversal`; then exactly equal to the jail path
   -> `path_binding`
7. securelevel: an integer (booleans rejected) inclusively within the jail's
   `securelevel_min`/`securelevel_max` -> `securelevel`
8. key: unknown kid -> `unknown_key`; non-active (e.g. revoked) kid ->
   `key_revoked`, even when the HMAC itself verifies
9. signature: recomputed HMAC mismatch -> `bad_signature`
10. iat window: `iat` must satisfy `now - max_age_seconds <= iat <=
    now + clock_skew_seconds` -> `iat_window`
11. replay: nonce already recorded in the store -> `nonce_replay`

The decision is `allow` only when every gate passes; `reason_codes` is then
`[]` and the nonce is recorded in the store as `{"ts": now_unix}`.

## Store and exit codes

Only an allow writes the store; a deny never mutates it. CLI exit codes:
allow = 0, deny = 1, load failure = 2. Load failure must not write the
store. No third-party dependencies are required; everything runs offline
with the Python standard library.
