# tidbrow admit rules

## Signing
`v1|{kid}|{tenant}|{table}|{op}|{pred}|{iat}|{nonce}`

pred is comma-separated cols; every col ∈ pred_allow; all pred_require present; reject deny substrings; tenant/table/op bind; HMAC+revoke; time; nonce allow-only.
