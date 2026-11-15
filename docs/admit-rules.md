# consulacl admit rules

## Signing input
`v1|{kid}|{token_id}|{ns}|{rules_csv}|{service_prefix}|{node}|{iat}|{nonce}`

## Bind
ns ∈ namespaces; set(rules) ⊆ rules_max; rules ∩ forbid_rules empty;
service_prefix ∈ service_prefixes; node ∈ nodes; len(token_id)==token_id_len;
HMAC+revoke; time; nonce allow-only.
