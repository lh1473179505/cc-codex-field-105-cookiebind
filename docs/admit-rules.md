# dhcpopt admit rules

subnet is a canonical IPv4 network accepted by `ipaddress.ip_network(strict=True)` and exactly matches a policy key; host bits are invalid. option_code is a JSON integer. Its decimal string selects an entry beneath that subnet's options. Codes in forbidden_options are always denied, and unregistered codes are not inferred from global DHCP defaults.

value_type exactly equals the selected option's type. For ipv4, value is a string parsed by `ipaddress.IPv4Address` and contained in one of that option's value_cidrs. A value accepted by another option or subnet is irrelevant.

pool_start and pool_end are IPv4 strings in the selected subnet, each contained in one pool_cidrs network, with numeric start <= end. Network containment uses IP semantics rather than string prefixes. All fields enter HMAC in the declared order. Key status, iat and nonce gates are enforced and denial never writes store.
