# jwezip admit rules

The outer `kid` identifies the admission HMAC key; `jwe_kid` independently selects the JWE recipient. Traverse `recipients[jwe_kid].algorithms[alg].encryptions[enc]`. An alg or enc valid under another recipient, or an enc not nested beneath the selected alg, is invalid.

`zip` is either the exact empty `uncompressed_zip_value` or a member of the selected enc entry's `zips`; compression support is not global across algorithms. `crit` is a unique, case-sensitive string list and a subset of `crit_allowed`. When zip is `DEF`, crit must be exactly `["zip"]`. When zip is empty, crit must be empty. Duplicates, unknown critical headers and a zip/crit disagreement are denied rather than normalized.

Preserve crit order in the complete signing line along with both key identifiers, alg, enc and zip. Enforce active-key HMAC and iat age/skew, consume nonce only for allow, and leave store untouched on every denial.
