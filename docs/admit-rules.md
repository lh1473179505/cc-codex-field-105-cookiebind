# mountns admit rules

Select policy.namespaces[namespace]. source and target are absolute canonical paths with no path_deny_substrings or empty/`.`/`..` component. source belongs to the namespace sources and target starts with one of its target_prefixes. fstype belongs to that namespace only.

flags is a unique list, a subset of flags and a superset of required_flags. propagation must equal the configured value, and read_only is exactly 0 or 1. For fstype=bind, source must additionally belong to bind_sources and read_only must be 1; a general source entry does not imply bind permission. Non-bind operations may be read-only or writable within these constraints. HMAC, revocation, iat freshness and allow-only nonce storage cover the complete request; denied mounts do not mutate store.
