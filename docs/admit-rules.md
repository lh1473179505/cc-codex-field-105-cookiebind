# agewrap admit rules

## Signing input
`v1|{kid}|{recipient}|{alg}|{aad}|{ct_hash}|{iat}|{nonce}`

## Gates
1. HMAC + kid_revoked.
2. recipient allowlist; alg allowlist; alg not in deny_alg_downgrade.
3. aad must start with one required_aad_prefixes.
4. iat age + nonce store allow-only.

## HMAC
Key `keys[kid].secret` is hex; the MAC is HMAC-SHA256 over the signing input
above, emitted as unpadded base64url and compared in constant time.

## Time window
`now - max_age_seconds <= iat <= now + clock_skew_seconds`.

## Nonce store
On allow, `store.items[nonce] = {"ts": now}`. An existing entry denies with
`nonce_replayed`; denies never mutate the store.

## Reason codes
- `malformed_box`: missing/empty required fields or non-integer `iat`.
- `unknown_kid`: `kid` absent from `keys`.
- `kid_revoked`: key status is not `active`.
- `malformed_key`: key secret is not valid hex.
- `bad_hmac`: signature mismatch.
- `recipient_not_allowed`: recipient outside `allowed_recipients`.
- `alg_not_allowed`: alg outside `allowed_algs`.
- `alg_downgrade_denied`: alg listed in `deny_alg_downgrade`.
- `aad_prefix_mismatch`: AAD starts with none of `required_aad_prefixes`.
- `iat_out_of_window`: `iat` outside the time window.
- `nonce_replayed`: nonce already present in the store.
