# istioauth admit rules

## Signing
`v1|{kid}|{principal}|{ns}|{path}|{method}|{iat}|{nonce}`

principal ∈ map; ns ∈ principals[p].ns; path startswith one paths (exact /healthz allowed if listed as prefix or exact); reject path_deny; method allow; HMAC+revoke; time; nonce allow-only.
