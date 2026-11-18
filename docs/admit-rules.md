# gitleaksr admit rules

Select `rules[rule_id]` and require `regex` to equal that rule's expression exactly. Do not broaden a token class, remove a named capture, or substitute another rule's expression. `entropy` is a JSON number, not a boolean or numeric string, in the inclusive rule-specific `entropy_min..entropy_max` range.

`keywords` is a unique, case-sensitive string list with inclusive size `keyword_count_min..keyword_count_max`. It must contain all `keywords_required` and only `keywords_allowed` entries. A prefilter keyword valid for another detector is insufficient.

`allowlist` is an object with exactly `allowlist_keys`. Both values are unique string lists. Every path is a safe relative glob without absolute prefixes or `path_deny_substrings`, and belongs to the selected rule's `allowlist_paths`; every stopword belongs to its `allowlist_stopwords`. Unknown allowlist mechanisms such as commits are invalid. `secret_group` is an integer within the global bounds and exactly equals the selected rule's capture index.

Sign regex, numeric entropy, ordered keywords, sorted allowlist keys and nested list order. Enforce active-key HMAC, iat age/skew and replay checks; denied rules never consume nonce or modify store.
