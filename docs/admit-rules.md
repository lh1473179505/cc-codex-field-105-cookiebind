# ctsubmit admit rules

log_id selects one CT log. chain is an ordered string array from leaf to intermediate and must equal one complete entry in that log's chains; reversed, truncated and cross-log chains are invalid. root_sha256 is exactly 64 lowercase hexadecimal characters and equals the selected log's root anchor.

not_before and not_after are canonical YYYY-MM-DDTHH:MM:SSZ UTC timestamps. not_before is at or after not_before_min, not_after is at or before not_after_max, not_after is strictly later, and their difference is at most max_validity_seconds. All temporal bounds belong to the selected log.

hostname is a lowercase DNS name with a non-empty leftmost label followed by one exact hostname_suffixes entry; a textual lookalike without the dot boundary is invalid. The chain order and all other fields are signed. HMAC/key status, iat and replay checks precede allow-only nonce persistence; deny leaves store unchanged.
