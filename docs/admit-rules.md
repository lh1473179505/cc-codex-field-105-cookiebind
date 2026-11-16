# ipsecprop admit rules

Select the profile before validating any other business field. local_id must be exact and peer_id must belong to that profile. Parse both selectors with `ipaddress.ip_network(strict=True)`; host bits are invalid. Each selector must be a subnet of at least one same-side supernet. A default route is forbidden even if a broad supernet were configured.

esp, ike and pfs must each be members of the profile lists; lifetime is inclusive between profile min/max. Membership in another profile is irrelevant. Verify the complete HMAC line, key status, iat window and allow-only nonce consumption. Never persist a denied proposal.
