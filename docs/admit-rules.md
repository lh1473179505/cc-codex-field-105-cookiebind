# clickhse admit rules

## Signing
`v1|{kid}|{database}|{table}|{user}|{format}|{iat}|{nonce}`

user ∈ users; database ∈ databases; table ∈ tables[database]; format ∈ formats and not in forbid_formats; reject ident_deny in database/table; HMAC+revoke; time; nonce allow-only.
