# oidcbackch admit rules

Traverse clients[client_id]. issuer must equal the client's issuer byte-for-byte, including the trailing slash; no host-case folding or slash stripping. aud must belong to audiences and, when require_aud_equals_client is true, must equal client_id.

sid starts with sid_prefix and meets sid_min_len. events is a unique string list of length 1..events_max, a subset of events_allowed, and contains every events_required URI; membership under another client does not count. jti_sha256 is exactly jti_hex_len lowercase hex characters.

delivery must be listed for the client. For http-post, endpoint must equal one endpoints entry. For poll, endpoint must equal one poll_endpoints entry and must not be taken from the http-post list. endpoint is an exact absolute HTTPS URL with no userinfo, query or fragment when forbid_endpoint_query is true. session_age is an integer within the client's inclusive [session_age_min, session_age_max].

Signing covers every business field in documented order. Active-key HMAC, revocation, iat age/skew and allow-only nonce consumption apply. Deny leaves store unchanged.

Verify HMAC-SHA-256 over the exact signing line in the documented field order. Reject unknown/revoked keys and stale or future iat values. A nonce is consumed only after every gate allows; every deny leaves store unchanged.
