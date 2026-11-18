# kevbind admit rules

`cve` must match `cve_pattern` and select one entry in `cves`; then `product` must select a product beneath that same CVE. A product known for another KEV entry does not establish this binding.

`due_date` is a real calendar date in exact zero-padded `YYYY-MM-DD` form, without a time or offset. It must lie within inclusive global `due_date_min..due_date_max` and exactly equal the selected product's KEV due date. Extending the deadline by one day is invalid rather than a harmless approximation.

`priority` and `owner` must each belong to the selected product's lists. `action` is a non-empty string of at most `action_length_max` characters and must exactly equal one of that product's registered actions. Cross-product actions, monitoring-only substitutions and case-folded owner names are invalid.

Sign CVE, product, due date, priority, owner and the complete action in declared order. Require known active-key HMAC, iat within max age and clock skew, and an unused nonce. Consume nonce and persist store only for a final allow.
