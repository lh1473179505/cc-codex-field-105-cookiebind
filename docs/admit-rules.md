# sysctlsec admit rules

key is a canonical lowercase dotted sysctl name with no empty, signed, whitespace or non-alphanumeric/underscore components, and must exactly select one settings entry. namespace must exactly equal that entry's namespace; a textual prefix or a namespace valid for another key is insufficient. Unregistered security sysctls are denied rather than handled by a generic integer rule.

value_type must equal the configured type. For integer, value is a JSON integer and booleans or numeric strings are invalid. value must lie in the inclusive value_min/value_max range and also occur in allowed_values. Range membership alone therefore cannot enable a value that the security policy explicitly excludes.

persistent is a JSON boolean exactly equal to the selected setting's persistence requirement, so a runtime-only write cannot impersonate the approved durable change. Sign key, type, value, namespace and persistence in the declared order. HMAC key status, iat freshness/skew and unused nonce are independent gates; only allow consumes nonce or saves store.
