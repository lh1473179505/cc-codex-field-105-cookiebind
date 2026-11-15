# linkerdx admit rules

## Signing
`v1|{kid}|{server}|{client}|{port}|{meshtls}|{iat}|{nonce}`

server ∈ servers; client ∈ clients; port ∈ ports; if require_meshtls then meshtls==1; HMAC+revoke; time; nonce allow-only.
