# kmsctx admit rules

Select key_id, then operation beneath that key. algorithm and grant must both belong to that exact operation; a grant valid for another operation on the same key is invalid. context keys must be a subset of context_allowed, contain every context_required key with its exact value and contain no context_forbidden key. An optional request_id must match request_id_pattern.

Encryption context is authenticated metadata, not a hint: never discard unknown keys or substitute required values. Verify HMAC over the exact `v1|` signing line in parts order, rendering context as sorted `key=value` pairs. Enforce key revocation, clock_skew_seconds/max_age_seconds and nonce consumption only after allow. Denials leave store unchanged.
