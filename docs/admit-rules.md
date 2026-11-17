# archrootx admit rules

## Signing
`v1|{kid}|{archive}|{entry}|{link_target}|{target_root}|{size}|{mode}|{uid}|{gid}|{iat}|{nonce}`

## Path / link
archive suffix ∈ list. entry rejects deny substrings; forbid absolute.
If mode ∈ symlink_modes or hardlink_modes: deny (forbid_symlink/hardlink).
Non-link entries require empty link_target.

## Root bind
target_root ∈ roots. uid/gid/mode/size must satisfy that root's allow lists / max_size.

HMAC+revoke; time; nonce allow-only.
