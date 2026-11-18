# fidoassert admit rules

rp_id selects credential IDs, UP/UV requirements, sign-count range and exact origins. credential_id must belong to the RP. up and uv are binary and required where configured. sign_count is a positive integer within the credential policy envelope. challenge_sha256 is 64 lowercase hex. origin is scheme+host+optional port only and must exactly match an allowed origin.

Verify HMAC-SHA-256 over the exact signing line in the documented field order. Reject unknown/revoked keys and stale or future iat values. A nonce is consumed only after every gate allows; every deny leaves store unchanged.
