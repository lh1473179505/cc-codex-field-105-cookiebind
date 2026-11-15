# envoyrbac admit rules

## Signing input
`v1|{kid}|{principal}|{path}|{method}|{headers_csv}|{iat}|{nonce}`

headers_csv: `k=v` joined by `,` with sorted keys (lowercase names in fixtures).

## Path / headers
Reject path deny substrings before prefix checks.
principal ∈ principals; path startswith one path_prefixes OR exact `/healthz` if listed;
method ∈ methods; every require_headers key present; if require value is not null, must equal;
none of deny_headers present; HMAC+revoke; time; nonce allow-only.
