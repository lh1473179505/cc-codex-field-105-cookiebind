# vexstmt admit rules

Select `products[product_purl].cves[cve]` using the exact, case-sensitive purl and a CVE matching `cve_pattern`. A CVE registered for another product is invalid. `status` must belong to that CVE's `statuses`.

For `not_affected`, `justification` must be one of the configured non-empty `justifications`. For every status whose configured justification list is empty, including `affected` and `fixed` here, `justification` must be the empty string. When `action_required` is true, `action_statement` is non-empty and starts with an `action_prefixes` entry; when false, it must be empty. Its length never exceeds `action_length_max`.

`issued_at` must be a UTC RFC3339 string in exact `YYYY-MM-DDTHH:MM:SSZ` form, with a real calendar date and inclusive value between `issued_at_min` and `issued_at_max`. Numeric offsets and other timestamp spellings are invalid.

Sign status, justification, action and issued_at together with product/CVE. Check active-key HMAC and iat freshness/skew; nonce is consumed and store saved only on allow.
