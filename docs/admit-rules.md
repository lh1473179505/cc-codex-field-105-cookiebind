# httpmacx admit rules

HTTP Message Signatures style base string (simplified).

## Base string

For each covered component in order, emit `"name": value` lines, then
`"@signature-params": ("c1" "c2");created=...;expires=...;keyid="...";nonce="..."`
Join with `\n`. HMAC-SHA256 → base64url.

## Gates

1. Recompute base string from request fields; verify sig; kid revoke.
2. required_covered ⊆ covered (order of covered is signing order; membership check for required).
3. method/authority allow; path prefix; if forbid_query_in_path and `?` in path => `query_in_path`.
4. content-type allow; if body_b64 present, content-digest must match sha-256 of body (base64url decode).
5. created/expires vs now ± skew; expired => `expired`.
6. nonce replay; write only allow.
