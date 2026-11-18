# tufrole admit rules

Traverse `repositories[repository].roles[role]`. `role` must be one of the four exact `role_names` and must exist beneath the selected repository; unknown names, aliases and case variants are invalid. Metadata registered for the same role in another repository has no authority here.

`version` is a JSON integer exactly equal to the selected role's registered version, not merely a positive or newer number. `threshold` is an integer exactly equal to that role's threshold and must also equal the number of supplied keyids. Numeric strings and booleans never satisfy either numeric field.

`keyids` is an ordered, unique string list. Every item matches `keyid_pattern`, and the complete list must exactly equal the role's registered keyids in the same order. Missing, additional, reordered or duplicated keyids are denied rather than normalized; threshold consistency alone cannot repair a wrong key list.

Preserve keyid order in the signing line and authenticate repository, role, version and threshold alongside it. Require an active-key HMAC, fresh non-future `iat` using the configured age/skew limits, and an unused nonce. Only allow consumes nonce or saves store.
