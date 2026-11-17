# ospflsa admit rules

Traverse area -> router_id -> lsa_type; membership under another area or router is irrelevant. area and router_id are canonical dotted IPv4 identifiers. Each type has its own lsid_cidrs set, and lsid must be an IPv4 address contained in at least one configured network. For a router LSA, require_router_lsid_identity additionally requires lsid == router_id.

age is an integer inclusively bounded by the selected area's age_min/age_max. sequence is an integer within the selected router's inclusive sequence range. payload_sha256 is exactly 64 lowercase hexadecimal characters and binds the LSA body to the admission object. Do not treat a valid LSID in another type's CIDR set as valid for the requested type.

The HMAC-SHA-256 signature digest includes every field in the specified order, including age, sequence and payload_sha256. Enforce key status, iat freshness/skew and nonce replay state; no denied LSA changes store.
