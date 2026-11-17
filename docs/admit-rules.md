# dnsupdate admit rules

zone is an exact policy key. owner is a lowercase absolute FQDN strictly beneath that zone with no empty labels; a suffix lookalike or relative name is invalid. rrtype and operation are resolved only beneath that zone and type.

rdata is an ordered array of unique IP strings parsed by `ipaddress.ip_address`. For add, it is non-empty, every address belongs to an rdata_cidrs network for that type, and ttl is an integer in the inclusive type range. For delete, rdata is exactly empty and ttl is exactly zero. An address valid for another record type or zone is not acceptable.

prerequisites is an object with exactly prerequisite_keys. host equals owner and serial is an integer in the zone's inclusive serial range. Sorted prerequisite keys, rdata order and all other fields enter HMAC. Revocation, iat freshness/skew and replay are enforced, and only allow changes store.
