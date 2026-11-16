# mailchain admit rules

## Signing input
`v1|{kid}|{from_addr}|{return_path}|{dkim_d}|{arc_i}|{cv}|{body_sha256}|{relay}|{iat}|{nonce}`

## Address parse
Split local@domain. Reject addr_deny_substrings. local not in from_local_deny.
from domain ∈ from_domains. return_path domain ∈ return_path_domains for that from domain.
dkim_d ∈ dkim_d list for that from domain.

## ARC / body / relay
arc_i in [0, arc_i_max]; cv ∈ cv_allow; forbid cv=fail.
If require_body_hash: len(body_sha256)==64 hex.
relay ∈ allowed_relays.

HMAC + revoke; time; nonce allow-only.
