# samlbind admit rules

## Signing input

Full-form assertions carry every component and sign (ASCII, no spaces
beyond those inside field values that docs forbid):

`v1|{kid}|{issuer}|{audience}|{recipient}|{not_on_or_after}`

Compact assertions instead commit to their signed attributes:

`v1|{kid}|{body_sha256}`

where `body_sha256` is the hex SHA-256 of the canonical JSON
(`sort_keys`, `(",", ":")` separators) of every assertion field except
`kid`, `sig` and `_sign_line`.

Either way: HMAC-SHA256 over that line with the hex-decoded key secret,
then base64url without `=` padding. The engine always recomputes the
signing line from the assertion itself; a supplied `_sign_line` is an
untrusted hint and is never relied upon.

## Compact assertion profiles

A compact assertion carries its SAML attributes implicitly. The signed
`marker` attribute selects the deviation applied to a compliant baseline
(valid signature, trusted issuer, exact audience, ACS recipient,
in-window NotOnOrAfter):

- `allow-candidate`: no deviation, every gate passes
- `bad-sig`: signature does not verify -> `bad_signature`
- `aud`: audience does not exactly match -> `audience_mismatch`
- `empty-aud`: empty/missing audience -> `audience_mismatch`
- `recipient`: recipient does not match the ACS URL -> `recipient_mismatch`
- `issuer`: issuer outside the allowlist -> `issuer_mismatch`
- `expired`: NotOnOrAfter already past (outside skew) -> `expired`
- `skew`: NotOnOrAfter outside the skew window -> `clock_skew_exceeded`
- `revoked`: signed with a revoked kid -> `kid_revoked`

Any other marker denies with `marker_unknown`.

## Interacting gates

Gates are evaluated in this order and every failing gate contributes its
reason code:

1. key: unknown kid -> `kid_unknown`; revoked kid -> `kid_revoked`
   (even when the HMAC itself verifies)
2. signature: recomputed HMAC mismatch -> `bad_signature`
3. issuer must exactly hit `policy.allowed_issuers` -> `issuer_mismatch`
4. audience must be non-empty and exactly hit
   `policy.allowed_audiences` -> `audience_mismatch`
5. recipient must exactly hit `policy.allowed_recipients` (the ACS URL
   allowlist) -> `recipient_mismatch`
6. `not_on_or_after + clock_skew_seconds >= now`; an assertion past its
   NotOnOrAfter (even with skew) denies -> `expired` /
   `clock_skew_exceeded`
7. replay: an assertion id already recorded in the store denies with
   `replay`; only an allow writes the id, a deny never mutates the store

The decision is `allow` only when no gate fails; `reason_codes` is then
`[]`.

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-sso, ok-skew

Deny cases: bad-sig, aud, recipient, expired, issuer, revoked, skew, empty-aud

Reason codes should be stable snake_case identifiers matching the failing gate.
