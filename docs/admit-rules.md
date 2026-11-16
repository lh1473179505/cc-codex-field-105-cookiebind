# pgptrust admit rules

## Signing input
`v1|{kid}|{key_fp}|{signer_fp}|{depth}|{algo}|{hash}|{notation}|{notation_val}|{body_sha256}|{iat}|{nonce}`

## Trust path
key_fp ∈ fps. signer_fp ∈ fps[key].signers AND signer_fp ∈ trusted_roots.
depth in [1, max_depth]. algo/hash ∈ lists; forbid md5 if forbid_md5.

## Notation
notation ∈ required_notations (must include the required ones — fixtures send exactly one that must match).
notation_val must equal notation_values[notation].
Reject notation_val containing notation_deny_substrings.

## Body
len(body_sha256)==body_sha256_len.

HMAC + revoke; time; nonce allow-only.
