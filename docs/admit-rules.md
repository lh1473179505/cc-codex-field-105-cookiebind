# mavenpgp admit rules

## Signing
`v1|{kid}|{group}|{artifact}|{version}|{fp}|{iat}|{nonce}`

key=`{group}:{artifact}` ∈ coords; version startswith version_prefixes; if forbid_snapshot and version endswith -SNAPSHOT deny; fp ∈ fps; HMAC+revoke; time; nonce allow-only.
