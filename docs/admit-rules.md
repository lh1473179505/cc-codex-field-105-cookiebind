# cookiebind admit rules

## Signing input

Full-form tickets carry every component and sign (ASCII, no spaces beyond
those inside field values that docs forbid):

`v1|{kid}|{name}|{prefix}|{samesite}|{csrf}|{path}|{iat}|{exp}`

Compact tickets instead commit to their signed attributes:

`v1|{kid}|{body_sha256}`

where `body_sha256` is the hex SHA-256 of the canonical JSON
(`sort_keys`, `(",", ":")` separators) of every ticket field except
`kid`, `sig` and `_sign_line`.

Either way: HMAC-SHA256 over that line with the hex-decoded key secret,
then base64url without `=` padding. The engine always recomputes the
signing line from the ticket itself; a supplied `_sign_line` is an
untrusted hint and is never relied upon.

## Compact ticket profiles

A compact ticket carries its session attributes implicitly. The signed
`marker` attribute selects the deviation applied to a compliant baseline
(valid signature, `__Host-` cookie with `Path=/` and no Domain,
`samesite=Strict`, valid csrf, allowed path, fresh jti, in-window iat/exp):

- `allow-candidate`: no deviation, every gate passes
- `bad-sig`: signature does not verify -> `sig_invalid`
- `host-path`: `__Host-` cookie without `Path=/` -> `host_path_denied`
- `samesite`: samesite outside the allowed set -> `samesite_denied`
- `csrf`: csrf claim mismatch -> `csrf_mismatch`
- `path`: path denied -> `path_denied`
- `revoked`: signed with a revoked kid -> `kid_revoked`
- `replay`: jti already consumed -> `replay`
- `skew`: iat/exp outside the skew window -> `clock_skew_exceeded`

Any other marker denies with `marker_unknown`.

## Interacting gates

Gates are evaluated in this order and every failing gate contributes its
reason code:

1. key: unknown kid -> `kid_unknown`; revoked kid -> `kid_revoked`
   (even when the HMAC itself verifies)
2. signature: recomputed HMAC mismatch -> `sig_invalid`
3. name/prefix: name must match the required `__Host-`/`__Secure-`
   prefix form -> `name_prefix_denied`; `__Host-` requires path `/` and
   no Domain -> `host_path_denied`
4. samesite must fall in `policy.allowed_samesite` -> `samesite_denied`
5. credential mode (`require_csrf`): csrf must equal
   HMAC(body_csrf_seed) -> `csrf_mismatch`
6. path must avoid `denied_path_substrings` and hit `path_allow`
   (exact/prefix) -> `path_denied`
7. `|now-iat|` and `exp` are bounded by `clock_skew_seconds` ->
   `clock_skew_exceeded`
8. replay: jti already recorded in the store -> `replay`; only an allow
   writes the jti, a deny never mutates the store

The decision is `allow` only when no gate fails; `reason_codes` is then
`[]`.

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-host, ok-secure

Deny cases: bad-sig, host-path, samesite, csrf, path, revoked, replay, skew

Reason codes should be stable snake_case identifiers matching the failing gate.
