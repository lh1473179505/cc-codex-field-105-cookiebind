# intotolay admit rules

Traverse supply_chain -> step_name and use only that step's policy. pubkey_ids are unique, must be a subset of pubkeys_allowed and must contain pubkeys_required. threshold is an integer within threshold_min/threshold_max and also cannot exceed the number of supplied unique keys; another step's keys or threshold do not establish validity.

Each artifact_rules item is `VERB path` with exactly one ASCII space. VERB belongs to artifact_verbs. path is relative, has no empty, `.` or `..` component, no configured dangerous substring, and starts with an allowed artifact_path_prefix. A terminal `*` may represent a wildcard only within an otherwise valid path prefix. artifact_rules is limited to artifact_rule_max entries and must contain every exact required rule; do not reorder or canonicalize rules before signing.

layout_sha256 is exactly 64 lowercase hexadecimal characters. The HMAC-SHA-256 digest binds supply-chain identity, ordered keys, threshold and artifact rules. Enforce key status, iat freshness/skew and replay protection; nonce is consumed only for allow and denied layouts never write store.
