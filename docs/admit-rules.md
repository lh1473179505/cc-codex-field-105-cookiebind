# quicconn admit rules

sni is a lowercase DNS name and exact service key; case folding, trailing dots and alternate names are not accepted. alpn and version are exact case-sensitive members of that service's lists, and an ALPN or version valid on another service cannot be borrowed.

transport_params has exactly the five configured keys. Integer parameters satisfy their inclusive min/max or exact values and booleans are not integers. disable_active_migration is a JSON boolean equal to its required value. Unknown parameters such as preferred_address are denied rather than ignored.

early_data has exactly enabled, max_bytes and alpn. enabled and alpn must match the service policy, alpn must also equal the connection ALPN, and max_bytes is an integer no greater than the service maximum and exactly zero when disabled. All nested parameters enter HMAC. Active key, iat within 600 seconds plus 60 seconds of future skew, and fresh nonce are required; denial does not mutate store.
