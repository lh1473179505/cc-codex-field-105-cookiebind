# mongocmd admit rules

## Signing
`v1|{kid}|{db}|{cmd}|{coll}|{user}|{iat}|{nonce}`

user bind db/coll/cmd; cmd not in forbid_cmds; reject ident_deny in db/coll; HMAC+revoke; time; nonce allow-only.
