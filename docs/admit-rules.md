# pypitwin admit rules

## Signing
`v1|{kid}|{project}|{issuer}|{sub}|{claim}|{iat}|{nonce}`

project ∈ projects; issuer exact; sub must startswith one of subs prefixes; claim ∈ claims; HMAC+revoke; time; nonce allow-only.
