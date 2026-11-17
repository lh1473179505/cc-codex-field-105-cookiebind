# azsas admit rules

Traverse account -> service -> resource and never borrow permissions or networks from another branch. path is a relative slash-separated object name under a resource path_prefix. Reject absolute paths and unsafe, empty, `.` or `..` components rather than cleaning them. permissions must be lexicographically sorted and unique, contain permissions_required and be a subset of permissions_allowed.

expiry is an integer lifetime in seconds after iat, inclusively bounded by the resource expiry_min/expiry_max; it is not a wall-clock timestamp. Parse source_ip with `ipaddress.ip_address` and require membership in a resource CIDR. https must equal require_https.

Verify HMAC over the exact `v1|` line in parts order with permissions joined by commas. Enforce key status, clock_skew_seconds/max_age_seconds and allow-only nonce use. Denials leave store unchanged.
