# bgpannounce admit rules

The peer IP selects one peer policy. as_path is a non-empty list of integer ASNs, its first ASN must equal the peer ASN, its length must not exceed as_path_max, and local_as must not appear when loop prevention is enabled. origin must be a member of that peer's origins; values allowed for another peer do not apply.

Parse prefix with `ipaddress.ip_network(strict=True)`, reject host bits and default routes, and require subnet containment in a peer prefix_supernets network. next_hop must be an IP address contained in a peer next_hop_cidrs network. communities are unique strings in `ASN:value` form, must be a subset of communities_allowed, and must contain communities_required. The AS path and communities are signed in their supplied order, not after sorting or deduplication.

The HMAC-SHA-256 digest covers the exact complete line, including prefix and next_hop. Apply active-key, iat freshness/skew and replay checks; only an allow consumes nonce, and every deny leaves store unchanged.
