# sfkeyx admit rules

## Signing input: `sf-dict-canonical`

The signed dictionary is every field except the envelope fields `kid`,
`sig` and `_sign_line` (`kid` is carried in the signing line itself, `sig`
is the signature, and `_sign_line` is an untrusted hint that is always
recomputed, never relied upon).

Canonical base string (ASCII), which pins both dictionary key order and
parameter order regardless of how the original JSON text arranged them:

- serialize the signed dictionary as canonical JSON: `sort_keys=True`,
  compact `(",", ":")` separators, `ensure_ascii=False`
- `body_sha256` = hex SHA-256 of that canonical JSON, UTF-8 encoded
- signing line = `v1|{kid}|{body_sha256}`

The signature is HMAC-SHA256 over that line using the hex-decoded key
secret, then base64url without `=` padding.

Canonical JSON also fixes the structured-field type markers: every value
must be a tagged scalar/container (`s` string, `i` integer, `b` boolean,
`d` object, `l` array). Floats and `null` have no type tag and are rejected,
and an empty signed dictionary is rejected.

## Interacting gates

Gates are evaluated in this order; every failing gate contributes its
reason code, and an allow requires every gate to pass:

1. key: unknown kid -> `kid_unknown`; revoked kid -> `kid_revoked`
   (a revoked kid denies even when the HMAC itself verifies)
2. signature: recomputed HMAC mismatch -> `bad_signature`
3. `sf-dict-canonical` structure:
   - dictionary key order deviation -> `key_order_invalid`
   - parameter order deviation -> `param_order_invalid`
   - unsupported/untagged value type -> `type_marker_invalid`
   - duplicate dictionary key -> `duplicate_key`
   - float value -> `float_not_allowed`
   - empty signed dictionary -> `empty_payload`

A compact request carries its structural deviation implicitly: the signed
`marker` attribute names the gate the presented dictionary fails
(`allow-candidate` clears every gate). Any other marker denies with
`unexpected_marker`.

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.
Only an allow records the request `id` into `store.items`.

## Fixture expectations

Allow cases: ok-dict, ok-params

Deny cases: bad-sig, order, type, param, revoked, dup-key, float, empty

Reason codes should be stable snake_case identifiers matching the failing gate.

| case | decision | reason_codes |
| --- | --- | --- |
| ok-dict | allow | `[]` |
| ok-params | allow | `[]` |
| bad-sig | deny | `["bad_signature"]` |
| order | deny | `["key_order_invalid"]` |
| type | deny | `["type_marker_invalid"]` |
| param | deny | `["param_order_invalid"]` |
| revoked | deny | `["kid_revoked"]` |
| dup-key | deny | `["duplicate_key"]` |
| float | deny | `["float_not_allowed"]` |
| empty | deny | `["empty_payload"]` |
