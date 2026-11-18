# devicecode admit rules

client_id selects user-code syntax, exact HTTPS verification URI, minimum interval and maximum expiry. device_code_sha256 is exactly 64 lowercase hex. user_code must exactly match the client pattern without case folding. interval and expires_in are integers within common and client limits. verification_uri cannot contain query, fragment, credentials or a trailing-path substitution.

Verify HMAC-SHA-256 over the exact signing line in the documented field order. Reject unknown/revoked keys and stale or future iat values. A nonce is consumed only after every gate allows; every deny leaves store unchanged.
