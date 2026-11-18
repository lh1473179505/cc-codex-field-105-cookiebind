# codeqlimp admit rules

Resolve `packs[pack].queries[query_id]`; a query registered under another pack is invalid. `query_id` must match `query_id_pattern` before lookup, with exactly three lowercase slash-separated components and no normalization of case or separators.

`language` must exactly equal the selected query language. `severity` and `precision` must be case-sensitive members of that query's respective lists. Valid values from another query or from general CodeQL documentation do not satisfy this registration.

`metadata` is a JSON object with exactly the keys in `metadata_required`; every value is a string and exactly equals the registered value. Missing keys, extra annotations, numeric severity values and alternate tag spellings are denied rather than merged or ignored.

Serialize metadata as sorted `key=value` pairs in the exact signing line and preserve every declared field. Verify HMAC-SHA-256 with an active known key, enforce `max_age_seconds` and `clock_skew_seconds` for iat, and consume nonce only after all gates allow. Every deny leaves store unchanged.
