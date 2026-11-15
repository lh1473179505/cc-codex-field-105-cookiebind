# nestclaim admit rules

## Signing input
`v1|{kid}|{typ}|{crit_csv}|{aud}|{sub}|{claim_path}|{claim_val}|{iat}|{exp}|{nonce}`

## crit
Every name in crit must ∈ allowed_crit; if require_all_crit, allowed_crit ⊆ crit (exact cover).
Unknown crit header => deny.

## claim_path
Must ∈ claim_path_allow; if forbid_path_dots_escape, reject `..` inside path.
claim_val must ∈ claim_values[claim_path].

## Other
typ/aud allowlists; sub must startswith one of sub_prefixes; HMAC+revoke; time; nonce allow-only.
