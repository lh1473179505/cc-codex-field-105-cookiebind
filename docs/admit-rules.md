# ovpnroute admit rules

username selects the complete push policy and common_name must be in that user's common_names. Parse client_cidr and route_cidr as strict IP networks: both must be canonical, client_cidr must be contained in a client_supernets entry, and route_cidr must be contained in a route_supernets entry. Never convert a host-bit CIDR or default route into an accepted network.

dns_domains has one to max_dns_domains unique lowercase names. Each name must either exactly equal a configured dns_suffix or end in `.` plus that suffix; suffix lookalikes are not members. dns_domains must contain every dns_required item, so a subdomain alone cannot replace a required apex. config_sha256 is exactly 64 lowercase hexadecimal characters.

All identities, networks, domain-list order and config digest are covered by the HMAC-SHA-256 signature. Apply revocation and iat freshness/skew, consume nonce only for allow, and leave store byte-for-byte unchanged for deny.
