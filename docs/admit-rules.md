# aclmask admit rules

path is a canonical absolute directory path and an exact policy key; traversal, repeated separators, backslashes and NUL are denied. Resolve entry_type and then principal only beneath that path. An identity registered for another path or under another entry type is not interchangeable. Names are case-sensitive exact strings.

permissions is a non-empty ordered list of unique one-character `r`, `w` or `x` items. It must be a subset of the selected entry's permissions_allowed and contain every permissions_required item. mask is not inferred from those permissions: it must exactly equal the path's case-sensitive mask string, including character order and omitted bits.

default and recursive are JSON booleans, not integers, and each exactly equals the selected path value. This prevents an access-ACL request from becoming a recursive default-ACL change. Sign the permission list in supplied order together with every other declared field. Enforce HMAC, revocation, iat freshness/skew and replay state; denied ACL changes leave nonce and store untouched.
