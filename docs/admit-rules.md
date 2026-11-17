# mtasts admit rules

domain selects policy_id, mode, MX, max_age and reporting constraints. policy_id must be a member of that domain's policy_ids and mode must be in its modes; an enforce-only domain cannot silently accept testing. report_domain must belong to the same domain's report_domains, providing exact report alignment rather than a loose public-suffix comparison.

mx contains mx_min through mx_max unique lowercase DNS hostnames. Every host must equal an mx_suffix or have one non-empty label before an allowed suffix boundary; all mx_required hosts must be present. MX hosts from another domain are not interchangeable. max_age is an integer within the inclusive domain bounds, and policy_sha256 is exactly 64 lowercase hexadecimal characters.

The HMAC-SHA-256 digest signs the ordered MX list together with policy ID, domain, mode, max_age and report_domain. Enforce key status, iat freshness/skew and replay protection; denied policies never consume nonce or otherwise modify store.
