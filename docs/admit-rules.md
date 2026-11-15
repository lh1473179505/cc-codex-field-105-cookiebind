# spiffejwt admit rules

## Signing input
`v1|{kid}|{td}|{sub}|{aud_csv}|{iat}|{exp}|{nonce}`

## Gates
1. HMAC + kid_revoked.
2. td allowlist; every aud in allowed_aud.
3. if sub_must_match_td: sub starts with `spiffe://{td}/`.
4. iat/exp skew; nonce store allow-only.

## Details

Signature: HMAC-SHA256 over the UTF-8 signing input using the key's
hex-decoded `secret`, emitted as base64url without padding. Comparison is
constant time.

1. `kid` must exist under `keys` with a `secret`; its `status` must be
   `active`. The signature must verify.
2. `td` must be in `allowed_td`; every entry of `aud` must be in
   `allowed_aud`.
3. When `sub_must_match_td` is true, `sub` must start with
   `spiffe://{td}/` (the trailing slash is significant).
4. Validity window at `now_unix`: reject when `now < iat - clock_skew_seconds`
   or `now >= exp`. Expiry is strict; the skew only tolerates future-dated
   `iat`. A `nonce` already present in the store is a replay. The store gains
   `{nonce: {"ts": now_unix}}` only when every gate passes, so a denial never
   consumes a nonce.

## Reason codes

| code | gate | meaning |
| --- | --- | --- |
| `malformed_svid` | - | missing/ill-typed required field |
| `kid_unknown` | 1 | `kid` has no key entry or no secret |
| `kid_revoked` | 1 | key status is `revoked` |
| `kid_inactive` | 1 | key status is neither `active` nor `revoked` |
| `bad_signature` | 1 | HMAC does not verify |
| `td_not_allowed` | 2 | `td` outside `allowed_td` |
| `aud_not_allowed` | 2 | one or more `aud` entries outside `allowed_aud` |
| `sub_td_mismatch` | 3 | `sub` does not start with `spiffe://{td}/` |
| `not_valid_yet` | 4 | `now < iat - clock_skew_seconds` |
| `token_expired` | 4 | `now >= exp` |
| `nonce_replayed` | 4 | nonce already recorded in the store |
