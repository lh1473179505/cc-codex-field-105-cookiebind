# parbind admit rules

client_id selects the exact redirect URI, PKCE method, claims policy and expiry envelope. redirect_uri is compared as a complete string with no query, fragment or userinfo. code_challenge is 43–128 unreserved base64url characters. claims keys are limited, required values exact, and max_age is a nonnegative decimal integer. expires_in is within the inclusive common and client limits.

Verify HMAC-SHA-256 over the exact signing line in the documented field order. Reject unknown/revoked keys and stale or future iat values. A nonce is consumed only after every gate allows; every deny leaves store unchanged.
