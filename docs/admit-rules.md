# grypematch admit rules

`package_purl` is an exact, case-sensitive canonical purl key; do not decode, lowercase or reconstruct it before lookup. `cve` must match `cve_pattern` and select an entry only beneath that package. The same CVE or fix information under another package has no bearing on this match.

`fix_state` must exactly equal the selected CVE's state, and `severity` must belong to its severity list with case preserved. A syntactically valid Grype state such as `fixed` cannot replace a registered `wont-fix` result.

When `ignore_required` is false, `ignore` must be the empty object. When true, it is an object with exactly `ignore_keys`; `condition` belongs to the selected CVE's `ignore_conditions`, and `expires_at` is a real canonical UTC timestamp in inclusive `ignore_expires_min..ignore_expires_max`. No other ignore key or indefinite exception is allowed.

Serialize a non-empty ignore with sorted keys in the signing line. Verify complete HMAC-SHA-256, key status and iat freshness/skew, then consume nonce only for allow. Denied matches leave store unchanged.
