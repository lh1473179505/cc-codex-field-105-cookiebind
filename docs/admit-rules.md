# ospflsa admit rules

Traverse area -> router_id -> lsa_type; membership under another area or router is irrelevant. area and router_id are canonical dotted IPv4 identifiers. Each type has its own lsid_cidrs set, and lsid must be an IPv4 address contained in at least one configured network. For a router LSA, require_router_lsid_identity additionally requires lsid == router_id.

age is an integer inclusively bounded by the selected area's age_min/age_max. sequence is an integer within the selected router's inclusive sequence range. payload_sha256 is exactly 64 lowercase hexadecimal characters and binds the LSA body to the admission object. Do not treat a valid LSID in another type's CIDR set as valid for the requested type.

The HMAC-SHA-256 signature digest includes every field in the specified order, including age, sequence and payload_sha256. Enforce key status, iat freshness/skew and nonce replay state; no denied LSA changes store.

## Reason codes

All applicable checks run on every admission; a report may carry multiple codes, and any non-empty list means `deny` with no store mutation.

- `malformed_lsa` / `malformed_field` / `malformed_lsid` / `malformed_nonce` / `malformed_store`: shape or type violation (booleans are not accepted as integers, IPv4 identifiers must be canonical dotted strings).
- `unknown_area` / `unknown_router` / `unknown_type`: the area, then the router within that area, then the LSA type within that router cannot be resolved.
- `lsid_outside_cidr`: `lsid` is not contained in any `lsid_cidrs` configured for the resolved type.
- `router_lsid_identity`: router LSA whose `lsid` differs from `router_id` while `require_router_lsid_identity` is set.
- `age_out_of_range`: `age` outside the resolved area's inclusive `age_min`/`age_max`.
- `sequence_out_of_range`: `sequence` outside the resolved router's inclusive `sequence_min`/`sequence_max`.
- `payload_digest_invalid`: digest length differs from `payload_sha256_hex_len` or contains non-lowercase hex when `require_lowercase_hex` is set.
- `unknown_key` / `key_revoked`: unknown `kid`, or a key whose `status` is not `active`.
- `bad_signature`: HMAC-SHA-256 over `v1|{kid}|{area}|{router_id}|{lsa_type}|{lsid}|{age}|{sequence}|{payload_sha256}|{iat}|{nonce}` (key secret decoded from hex, digest encoded as unpadded base64url) does not match `sig`.
- `iat_out_of_window`: `iat` not within `[now - max_age_seconds, now + clock_skew_seconds]`.
- `nonce_replay`: the nonce already exists in the store.

On `allow`, the store records `items[nonce] = {"ts": now_unix}`; the CLI returns exit code 0 for allow and 1 for deny, writing the report in both cases but persisting the store only on allow.
