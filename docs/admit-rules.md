# kmipwrap admit rules

The profile controls key_id prefixes, wrapping_key, algorithm, usage and encoding. key_id is a relative slash-separated identifier with no empty, `.` or `..` component. wrapping_key must be exact for the profile. algorithm selects the allowed key_bytes list; the supplied length must match one entry exactly.

usage must be unique, contain usage_required and be a subset of usage_allowed. encoding must be allowed for the profile. No rule may be satisfied using another profile's configuration. Sign every field, reject revoked keys and stale/future iat, and mutate nonce store only after a complete allow.
