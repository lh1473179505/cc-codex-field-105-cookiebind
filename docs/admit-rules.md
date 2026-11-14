# wgpeer admit rules

## Signing input
`v1|{kid}|{pubkey}|{endpoint}|{allowed_ips_csv}|{iat}|{nonce}`

## Gates
1. HMAC + kid_revoked.
2. pubkey allowlist; endpoint ends with allowed_endpoint_suffixes.
3. each allowed_ip must start with allowed_ip_prefixes; if forbid_default_route, reject 0.0.0.0/0 and ::/0.
4. iat age + nonce store allow-only.
