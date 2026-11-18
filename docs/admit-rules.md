# rekorlog admit rules

Select `logs[log_id]`, then resolve `kinds[kind]` only inside that log. The entry kind is case-sensitive and cannot borrow a definition from another log. `body_sha256` must be exactly `sha256_hex_length` lowercase hexadecimal characters and exactly equal the digest registered for that log/kind pair; a syntactically valid digest for different content is insufficient.

`public_key` must exactly equal one of the selected kind's `public_keys`, including algorithm, encoded key material and comment. Do not treat a key trusted by another log or kind as interchangeable. `log_index` is a JSON integer, not a string or boolean, in the inclusive log-specific `log_index_min..log_index_max` range.

`integrated_time` is a real UTC calendar timestamp in exact `YYYY-MM-DDTHH:MM:SSZ` form, with no offset or fractional seconds, and lies inclusively between the selected log's `integrated_time_min` and `integrated_time_max`. These are independent bounds; a valid timestamp from another log's window does not pass.

The signing line covers log, kind, body digest, public key, index and integrated time in declared order. Verify HMAC with an active key, enforce `iat` freshness under `max_age_seconds` and `clock_skew_seconds`, and reject a previously used nonce. Consume nonce and save store only after every gate allows; every deny leaves store unchanged.
