# recoveryx admit rules

user_id selects recovery-code syntax, channel, attempt limit and used-count ceiling. code_sha256 is 64 lowercase hex and code_format must exactly match the user's pattern. channel belongs to that user. attempt starts at one and must not exceed attempt_max. used_count must not exceed used_max; a previously used recovery code cannot be redeemed again. Counters are signed rather than trusted from an unsigned side channel.

Verify HMAC-SHA-256 over the exact signing line in the documented field order. Reject unknown/revoked keys and stale or future iat values. A nonce is consumed only after every gate allows; every deny leaves store unchanged.
