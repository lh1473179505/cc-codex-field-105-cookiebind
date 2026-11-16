# krbrealm admit rules

SPN syntax is `service/host@REALM`; the realm suffix must equal the top-level realm. Look up that realm, then require service in services and host to end with one host_suffixes entry. Do not normalize away a mismatched realm.

The enctypes set must be a subset of the realm set and contain required_enctype. pac must be 1 when require_pac is true. client must start with a realm client_prefix. Parse every addresses item with `ipaddress.ip_address`; require one to max_addresses unique addresses, each contained in a realm client_cidrs network.

Verify HMAC over the exact signing line, reject revoked/unknown keys, enforce iat freshness/skew, and consume nonce only on allow. Denials leave store unchanged.
