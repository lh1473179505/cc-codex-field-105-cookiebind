# tfunlock admit rules

## Signing input
`v1|{kid}|{lock_id}|{workspace}|{backend}|{who}|{iat}|{nonce}`

## Bind
workspace ∈ workspaces; backend ∈ workspaces[ws].backends; who ∈ owners;
lock_id length lock_id_hex_len hex; backend must not contain deny substrings.
HMAC+revoke; time; nonce allow-only.
