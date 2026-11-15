# mtlsmap admit rules

## Signing input

Full-form mappings carry every component and sign (ASCII, no spaces
beyond those inside field values that docs forbid):

`v1|{kid}|{fp}|{uri_san}|{role}|{not_after}`

Compact mappings instead commit to their signed attributes:

`v1|{kid}|{body_sha256}`

where `body_sha256` is the hex SHA-256 of the canonical JSON
(`sort_keys`, `(",", ":")` separators) of every mapping field except
`kid`, `sig` and `_sign_line`.

Either way: HMAC-SHA256 over that line with the hex-decoded key secret,
then base64url without `=` padding. The engine always recomputes the
signing line from the mapping itself; a supplied `_sign_line` is an
untrusted hint and is never relied upon.

## Compact mapping profiles

A compact mapping carries its peer attributes implicitly. The signed
`marker` attribute selects the deviation applied to a compliant baseline
(valid signature, allowlisted fingerprint, policy-matching URI SAN,
authorized non-empty role, in-window not_after):

- `allow-candidate`: no deviation, every gate passes
- `bad-sig`: signature does not verify -> `bad_signature`
- `fp`: fingerprint does not hit the allowlist -> `fp_not_allowed`
- `uri`: URI SAN outside the spiffe-like prefix policy -> `uri_san_mismatch`
- `case-uri`: URI SAN matches only case-insensitively -> `uri_san_mismatch`
- `role`: role not authorized -> `role_not_allowed`
- `empty-role`: empty/missing role -> `role_not_allowed`
- `expired`: not_after already past (outside skew) -> `expired`
- `revoked`: signed with a revoked kid -> `kid_revoked`

Any other marker denies with `marker_unknown`.

## Interacting gates

Gates are evaluated together and every failing gate contributes its
reason code:

1. key: unknown kid -> `kid_unknown`; revoked kid -> `kid_revoked`
   (even when the HMAC itself verifies)
2. signature: recomputed HMAC mismatch -> `bad_signature`
3. fp must be non-empty and hit `policy.allowed_fingerprints`
   (exact, case-sensitive) -> `fp_not_allowed`
4. uri_san must start with `spiffe://` and literally (case-sensitively)
   match one of `policy.allowed_uri_san_prefixes` -> `uri_san_mismatch`
5. role must be non-empty and hit `policy.allowed_roles`
   -> `role_not_allowed`
6. `not_after + clock_skew_seconds >= now`; a mapping past its
   not_after (even with skew) denies -> `expired`
7. replay: a mapping id already recorded in the store denies with
   `replay`; only an allow writes the id, a deny never mutates the store

The decision is `allow` only when no gate fails; `reason_codes` is then
`[]`.

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-pay, ok-ops

Deny cases: bad-sig, fp, uri, role, expired, revoked, case-uri, empty-role

Reason codes should be stable snake_case identifiers matching the failing gate.
