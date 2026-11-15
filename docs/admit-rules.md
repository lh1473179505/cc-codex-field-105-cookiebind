# sqlinjx admit rules

## Signing input
`v1|{kid}|{schema}|{table}|{op}|{params_csv}|{where_cols}|{iat}|{nonce}`

## Ident safety
schema/table/op/where col names: reject ident_deny_substrings; if require_lowercase_idents must be lowercase.
schema ∈ schemas; table ∈ schemas[s].tables; op ∈ schemas[s].ops.
where_cols is comma-separated; each ∈ where_allow; count <= where_cols_csv_max.
len(params) <= params_max; HMAC+revoke; time; nonce allow-only.
