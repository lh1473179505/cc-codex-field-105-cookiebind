# keyringx admit rules

keyring selects one keyring policy and key_type is resolved only beneath it. payload_length is a JSON integer, excluding booleans and numeric strings, within the selected type's inclusive payload_min/payload_max range. A type or length valid in another keyring cannot be substituted for the selected pair.

permissions is a non-empty ordered list of unique strings, a subset of permissions_allowed and a superset of permissions_required for the selected keyring. timeout is a JSON integer within the inclusive keyring timeout range. link must exactly equal one of that keyring's link_targets and, when forbid_self_link is true, cannot equal keyring; no arbitrary existing keyring name is acceptable.

The signature preserves permissions order and covers key type, payload length, timeout and link together with all other fields. Verify HMAC-SHA-256, key status, iat freshness/skew and nonce uniqueness before any allow. Only allow consumes nonce or saves store; denial has no persistent side effect.
