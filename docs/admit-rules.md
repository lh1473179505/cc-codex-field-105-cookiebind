# certpath admit rules

## Signing input
`v1|{kid}|{leaf}|{chain_csv}|{eku}|{dns}|{iat}|{exp}|{nonce}`

## Chain
len in [min,max]; if require_chain_leaf_first: chain[0]==leaf; chain[-1] ∈ trusted_roots;
if forbid_duplicate_certs: unique names.

## Gates
eku allowlist; dns endswith allowed_dns_suffixes; HMAC+revoke; time; nonce allow-only.
