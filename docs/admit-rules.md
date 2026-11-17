# cabasem admit rules

profile selects every issuance constraint. not_before/not_after are integer Unix seconds, not_before < not_after, and their difference is inclusively bounded by validity_min_seconds/validity_max_seconds. key_alg selects the profile key_pairs entry and key_bits must be a member of that algorithm's list; a size valid for another algorithm or profile is insufficient.

san_dns has profile-specific inclusive cardinality, unique lowercase DNS names and no wildcards unless explicitly allowed. Every SAN must equal a san_suffix or end in `.` plus that suffix with non-empty labels. eku is unique, contains all eku_required values and is a subset of eku_allowed; an empty required set is different from an omitted field and this policy requires the stated values.

der_sha256 is exactly 64 lowercase hexadecimal characters. The HMAC-SHA-256 signature covers the ordered SAN/EKU lists, validity, key pair and digest. Enforce revoked/unknown keys, iat freshness/skew and nonce replay without mutating store for any denied certificate.
