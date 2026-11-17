# ldplabel admit rules

The peer address selects exactly one policy and lsr_id must equal that peer's configured LSR ID. Parse fec using `ipaddress.ip_network(strict=True)`; require a canonical network contained in a peer fec_supernets entry and reject a default FEC. String prefix matching is not CIDR containment.

transport_address must be an IP address inside the peer transport_cidrs set and, when transport_must_equal_peer is true, exactly equal peer. label is an integer in the inclusive peer range but must not occur in reserved_labels, even when that reserved value lies inside the range. binding_sha256 is exactly 64 lowercase hexadecimal characters.

The signature digest covers peer, LSR identity, FEC, transport and label together with the remaining fields. Unknown/revoked keys, stale or future iat and used nonce values are denied; nonce state changes only after allow and denied bindings never write store.
