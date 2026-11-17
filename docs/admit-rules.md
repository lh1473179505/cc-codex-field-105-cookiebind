# nftbindx admit rules

## Signing
`v1|{kid}|{table}|{chain}|{iface}|{set}|{elem}|{action}|{jump}|{priority}|{iat}|{nonce}`

## Cross binds
table/chain/iface maps. If set_required_for[table]: set must exist and elem ∈ set (exact or host-in-CIDR via ipaddress).
Reject elem deny substrings. action ∈ allowed_actions.
If action==jump: jump must be non-empty and ∈ jump_targets[table]; else jump must be empty.
priority must fall in priority_bands[table].

HMAC+revoke; time; nonce allow-only.
