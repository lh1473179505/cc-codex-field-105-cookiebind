# sessionrev admit rules

Traverse client_id -> user_id, then bind sid prefix and device_id to that user. reason belongs to the user/client policy. effective_in is an integer from zero through the configured maximum, so immediate-only clients cannot schedule delayed revocation. device_id matches the safe lowercase form and is registered to the same user. All fields are covered by the signature.

Verify HMAC-SHA-256 over the exact signing line in the documented field order. Reject unknown/revoked keys and stale or future iat values. A nonce is consumed only after every gate allows; every deny leaves store unchanged.
