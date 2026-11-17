# ntpsource admit rules

profile selects one complete upstream-source policy. hostname equals the profile hostname exactly and ip_address is parsed by `ipaddress.ip_address`, then contained in one of that profile's ip_cidrs. A hostname or address valid under another profile does not satisfy this binding.

stratum is a JSON integer in strata and refid is an exact case-sensitive string in refids. minpoll and maxpoll are integer base-two polling exponents within both the global exponent bounds and the profile's inclusive poll_min/poll_max range, with minpoll <= maxpoll. auth_key exactly matches one of the profile auth_keys.

The complete field order is authenticated, including both poll exponents and auth_key. Unknown/revoked signing keys, iat outside the permitted window and used nonces are denied. No denied source mutates store.
