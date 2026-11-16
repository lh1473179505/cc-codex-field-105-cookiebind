# sarifimp admit rules

rule_id and level are looked up beneath the selected tool; a rule known to another tool is not valid. uri is a relative source path under one of the tool uri_prefixes. Reject unsafe substrings, absolute paths, empty/`.`/`..` components and encoded traversal rather than cleaning them.

Line numbers are integers in [line_min,line_max], with start_line <= end_line. fingerprint keys must be in allowed_fingerprint_keys, include all required_fingerprints for the tool, and each value length must be within configured bounds. The signing representation sorts fingerprint keys and joins `key=value` with commas. Enforce HMAC/revocation/iat and nonce only on allow; deny leaves store unchanged.
