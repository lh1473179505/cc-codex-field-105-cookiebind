# awssigv admit rules

Select service first, then require region and method to belong to that service. canonical_path is an absolute slash-prefixed path beneath a service path_prefix. Reject empty, `.` or `..` components, backslashes, repeated slashes, encoded dot/slash traversal and NUL; never normalize a dangerous path into an allowed one.

canonical_query keys must be unique JSON object keys from query_allowed and include every query_required key with its exact string value. signed_headers must be lowercase, lexicographically sorted and unique, contain headers_required and be a subset of headers_allowed. payload_sha256 is exactly 64 lowercase hex characters; methods listed in empty_payload_methods must use empty_payload_sha256.

Verify HMAC over the exact `v1|` signing line in parts order, with canonical_query rendered as sorted `key=value` pairs and signed_headers joined by commas. Enforce active keys, clock_skew_seconds/max_age_seconds and allow-only nonce consumption. Denials leave store unchanged.
