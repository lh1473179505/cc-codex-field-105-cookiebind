# semgrepr admit rules

`rule_id` must match `rule_id_pattern` and select exactly one `rules` entry. `languages` is a unique, case-sensitive string list with inclusive size `language_count_min..language_count_max`, and the complete ordered list must exactly equal the selected rule's `languages`; duplicates are not silently removed.

`pattern_form` must belong to the rule's `pattern_forms`. `pattern` is a non-empty string of at most `pattern_length_max` characters, starts with the exact selected form followed by a colon, and equals the registered pattern byte-for-byte, including indentation and newlines. A shorter or semantically broader pattern is not equivalent.

`severity` belongs to the selected rule's severities. `paths_exclude` is a unique list of at most `exclude_count_max` relative slash-separated globs, containing every `paths_required` item and only `paths_allowed` items. Reject absolute paths, empty components, `.`/`..`, backslashes and NUL before membership checks; never clean an unsafe exclusion into an allowed one.

Preserve language and exclusion order in the signing line. Require active-key HMAC-SHA-256, valid iat age/skew and an unused nonce. Only a final allow consumes nonce or saves store.
