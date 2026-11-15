# sparkacl admit rules

## Signing
`v1|{kid}|{app}|{user}|{master}|{jars}|{iat}|{nonce}`

app bind user/master; jars must startswith one jar_prefixes; reject deny substrings; HMAC+revoke; time; nonce allow-only.
