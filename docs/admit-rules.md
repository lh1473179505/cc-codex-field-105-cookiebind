# podsecx admit rules

## Signing
`v1|{kid}|{name}|{ns}|{privileged}|{caps}|{root_fs}|{iat}|{nonce}`

caps is comma-separated (empty ok). ns ∈ namespaces; privileged must be 0 if not allow_privileged; every cap ∈ allowed_caps and not in forbid_caps; if require_read_only_root then root_fs==ro; reject name deny substrings; HMAC+revoke; time; nonce allow-only.
