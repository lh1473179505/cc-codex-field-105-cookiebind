# rfc3161 admit rules

Select `tsas[tsa]` using the exact HTTPS URI. `digest_alg` must select that TSA's `digest_algorithms` entry, and `message_imprint` must be lowercase hexadecimal with exactly the length registered for that algorithm. A digest size or algorithm accepted by another TSA is not interchangeable.

`request_nonce` matches `request_nonce_pattern` and starts with the selected TSA's `request_nonce_prefix`; it is distinct from the outer replay nonce. `cert_req` is a JSON boolean, never a string, and must occur in `cert_req_values`. `policy_oid` must exactly equal one of the same TSA's `policy_oids`, with no default-policy fallback.

The signed line covers the TSA, algorithm, imprint, RFC 3161 request nonce, certReq and policy OID as well as the outer nonce. Require active-key HMAC and a fresh iat under the age/skew limits. Only allow consumes the outer nonce or saves store.
