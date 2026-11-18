# zapscan admit rules

Select `contexts[context]`; target and rule resolution remain beneath that context. Parse `target_url` as a URL and require HTTPS, no username/password userinfo, no query and no fragment. The original URL string must then exactly equal one of the context's `target_urls`; do not normalize a lookalike host, remove a query, or borrow another context's target.

`scan_rule` must select a rule beneath the context. `threshold` and `strength` are exact case-sensitive members of that rule's lists, including any special value such as INSANE only when explicitly registered. A rule known globally but absent from the selected context is invalid.

`auth` is required and must exactly equal the context's complete authentication object. Its method selects the exact key set in `auth_keys_by_method`; additional passwords, tokens or script fields are denied rather than ignored. Form login URLs and script names cannot be exchanged between contexts, and no unauthenticated fallback exists.

The exact signing line covers target, rule tuning and every auth field with sorted auth keys. Verify active-key HMAC-SHA-256, iat age/skew and unused nonce. Only allow consumes nonce and saves store.
