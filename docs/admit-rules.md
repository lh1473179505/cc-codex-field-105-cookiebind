# cibareq admit rules

Select client_id and bind login_hint prefix, binding_message regular expression, polling interval, expiry and scope to that client. Hints are printable single tokens. binding_message is bounded and must exactly match the client pattern. scope is a unique list, contains openid, stays within client scope and count limits. interval and expiry are integers within common/client limits.

Verify HMAC-SHA-256 over the exact signing line in the documented field order. Reject unknown/revoked keys and stale or future iat values. A nonce is consumed only after every gate allows; every deny leaves store unchanged.
