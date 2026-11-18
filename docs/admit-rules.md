# oidclogout admit rules

client_id fixes issuer including trailing slash, sid prefix, exact post-logout URI and locale allowlist. sid and state meet minimum length and contain no controls. post_logout_uri is exact with no userinfo/query/fragment. ui_locales are unique, counted and drawn from the client list. Logout state does not authorize a URI belonging to another client.

Verify HMAC-SHA-256 over the exact signing line in the documented field order. Reject unknown/revoked keys and stale or future iat values. A nonce is consumed only after every gate allows; every deny leaves store unchanged.
