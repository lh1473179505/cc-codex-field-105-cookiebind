# relreqx admit rules

## Signing input

Full-form requests carry every component and sign (ASCII, no spaces
beyond those inside field values that docs forbid):

`v1|{kid}|{origin}|{referer}|{mode}|{dest}`

Compact requests instead commit to their signed attributes:

`v1|{kid}|{body_sha256}`

where `body_sha256` is the hex SHA-256 of the canonical JSON
(`sort_keys`, `(",", ":")` separators) of every request field except
`kid`, `sig` and `_sign_line`.

Either way: HMAC-SHA256 over that line with the hex-decoded key secret
(a secret that is not valid hex falls back to its UTF-8 bytes), then
base64url without `=` padding. The engine always recomputes the signing
line from the request itself; a supplied `_sign_line` is an untrusted
hint and is never relied upon.

## Compact request profiles

A compact request carries its attributes implicitly. The signed `marker`
attribute selects the deviation applied to a compliant baseline (valid
signature, `https://example.com` origin with a same-site https referer,
`mode=cors`, empty destination, canonical lowercase host, fresh id):

- `allow-candidate`: no deviation, every gate passes
- `bad-sig`: signature does not verify -> `sig_invalid`
- `site`: referer is schemeful cross-site -> `site_mismatch`
- `mode`: navigation type outside the allowed cors/navigate table ->
  `mode_not_allowed`
- `dest`: destination outside the policy or not bound to its mode ->
  `dest_not_allowed`
- `null-origin`: literal `null` origin while `allow_null_origin` is
  false -> `null_origin_denied`
- `http-downgrade`: cleartext http origin (or an https origin referred
  from an http page) -> `http_downgrade`
- `case-host`: host spelled with uppercase letters ->
  `host_case_mismatch`
- `revoked`: signed with a revoked kid -> `kid_revoked`

Any other marker denies with `marker_unknown`.

## Interacting gates

Gates are evaluated in this order and every failing gate contributes its
reason code:

1. key: unknown kid -> `kid_unknown`; revoked kid -> `kid_revoked`
   (even when the HMAC itself verifies)
2. signature: recomputed HMAC mismatch -> `sig_invalid`
3. origin: the literal `null` origin is accepted only when
   `policy.allow_null_origin` is true, otherwise `null_origin_denied`
4. downgrade: an http origin, or an https origin with an http referer,
   -> `http_downgrade`; downgraded requests skip the origin/site tables
5. origin table: case-insensitive scheme/host/port membership of
   `policy.trusted_origins` -> `origin_denied`
6. same-site: schemeful site of origin and referer must be equal
   (scheme always participates; registrable domain approximated by the
   last two DNS labels offline) -> `site_mismatch`
7. mode: must fall in `policy.allowed_modes` (cors/navigate) ->
   `mode_not_allowed`
8. dest binding: the destination must be in `policy.allowed_dests` and
   in the destinations `policy.mode_dests` binds to this mode ->
   `dest_not_allowed`
9. host case: an uppercase host in origin or referer fails the canonical
   host binding -> `host_case_mismatch`
10. replay: request id already recorded in the store -> `replay`; only
    an allow writes the id, a deny never mutates the store

The decision is `allow` only when no gate fails; `reason_codes` is then
`[]`.

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-same, ok-cors

Deny cases: bad-sig, site, mode, dest, revoked, null-origin, http-downgrade, case-host

Reason codes should be stable snake_case identifiers matching the failing gate.

Expected mapping:

| case | reason_codes |
| --- | --- |
| bad-sig | `sig_invalid` |
| site | `site_mismatch` |
| mode | `mode_not_allowed` |
| dest | `dest_not_allowed` |
| revoked | `kid_revoked` |
| null-origin | `null_origin_denied` |
| http-downgrade | `http_downgrade` |
| case-host | `host_case_mismatch` |
