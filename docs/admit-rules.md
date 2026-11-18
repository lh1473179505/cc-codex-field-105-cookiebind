# tlskeylog admit rules

Select `profiles[profile]`. `session_id` matches `session_pattern` and starts with one of that profile's `session_prefixes`; a session valid under another profile is invalid. `client_random` is exactly `client_random_hex_length` lowercase hexadecimal characters, with no uppercase normalization or prefix truncation.

`label` selects an entry only beneath that profile. Integer `secret_length` must belong to that label's `secret_lengths`, `purpose` must belong to its `purposes`, and integer `retention_seconds` must exactly occur in its `retention_values`. TLS 1.2 master-secret sizing and TLS 1.3 traffic-secret sizing are not interchangeable, and a longer retention allowed for one label does not extend another label.

Authenticate session, random, label, size, purpose and retention in the declared order. Require active-key HMAC and iat freshness under age/skew limits. Consume nonce and save store only on allow; denied key-log access has no state side effects.
