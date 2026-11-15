# trinoacl admit rules

## Signing
`v1|{kid}|{catalog}|{schema}|{table}|{user}|{iat}|{nonce}`

user bind catalog/schema; table key is `{catalog}.{schema}`; reject ident_deny in schema/table (`.` only forbidden inside schema/table names themselves — fixtures use `;`); HMAC+revoke; time; nonce allow-only.
