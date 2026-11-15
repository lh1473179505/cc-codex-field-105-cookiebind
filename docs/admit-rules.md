# purlseal admit rules

## Signing input
`v1|{kid}|{purl}|{registry}|{name}|{version}|{digest}|{license}|{iat}|{nonce}`

## PURL binding
purl must start with one of allowed_types; name/version must appear in purl (`/{name}@{version}`).
If forbid_uppercase_in_purl / require_lowercase_name: name and purl name segment must be lowercase.

## Gates
registry/license allowlists; denied_names; digest must use digest_alg prefix and 64-hex; HMAC+revoke; time; nonce allow-only.
