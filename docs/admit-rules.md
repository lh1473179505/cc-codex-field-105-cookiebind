# gitgpgx admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{tree}|{parents_csv}|{trailer_sha}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- kid 在 trust_store 且 level>=policy.min_trust
- tree 哈希绑定；parents 集合匹配
- 必需 trailer 键值
- 吊销与过期

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-main, ok-merge

Deny cases: bad-sig, trust, tree, trailer, revoked, parent, expired, extra-parent

Reason codes should be stable snake_case identifiers matching the failing gate.

## Reference derivation

- Content fields: all object fields except `kid`, `sig`, and `_`-prefixed
  metadata. `tree` = SHA-256 of the canonical JSON of the content fields
  (sorted keys, compact separators, UTF-8).
- `parents_csv` joins the sorted declared `parents` (default none);
  `trailer_sha` is the SHA-256 of the canonical JSON of the declared
  `trailers` (default none). Empty trailing fields are omitted from the
  signing line, so an object with no parents or trailers signs
  `v1|{kid}|{tree}`.
- The trust store is the keys file. A key's `level` defaults to 1 when
  `status` is `active` and 0 otherwise; `policy.min_trust` defaults to 1.
  `status: revoked` denies even when the HMAC verifies (`kid_revoked`).
- Tree binding also requires `path` to sit under the policy tree root:
  `policy.allowed_path_roots`, defaulting to `/v1/{policy.pkg}/`.
- Parents set match: the declared `parents` set must equal the set of ids
  already admitted in the store (`store.items` keys).
- Required trailers come from `policy.required_trailers` (default none).
- Expiry: an `expires` unix timestamp on the key or on the object is
  evaluated against `now` with `policy.clock_skew_seconds` tolerance.
- On allow the admitted id is recorded in `store.items` with the admission
  timestamp; on deny the store is never modified.
