# dnsrpz admit rules

zone is a lowercase absolute RPZ zone and selects actions, QNAME suffixes, CNAME suffixes and TTL bounds. qname is a lowercase relative DNS name without a final dot; it must equal a qname_suffix or end at a dot-label boundary before one. A wildcard, when allowed, is exactly one leading `*.` component. Embedded, repeated or suffix wildcards are invalid.

owner must be the literal concatenation `qname + '.' + zone`, preserving the wildcard and the final root dot. Do not normalize owner independently from qname. action belongs to the zone's action set. For CNAME, cname_target is a non-empty lowercase absolute name equal to or beneath a configured CNAME suffix; for every other action it must be empty.

ttl is an integer inside the inclusive zone range and rule_sha256 is exactly 64 lowercase hexadecimal characters. The HMAC digest covers the exact zone/owner/qname/action/CNAME/TTL sequence and all remaining fields. Revocation, iat and replay gates apply, and no deny may write store.
