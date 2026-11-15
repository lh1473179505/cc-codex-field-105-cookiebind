# dnsowner admit rules

## Signing input
`v1|{kid}|{owner}|{rrtype}|{rdata}|{ttl}|{iat}|{nonce}`

## Owner normalize
If require_lowercase: owner must be lowercase. If require_absolute: must end with `.`.
If forbid_empty_label: reject `..`. Owner must endswith one of allowed_zones.

## Gates
rrtype allowlist; ttl in [min,max]; TXT rdata must startswith one of txt_prefix_allow when type=TXT;
HMAC+revoke; time; nonce allow-only.
