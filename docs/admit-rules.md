# xmlenc admit rules

Traverse `recipients[recipient].key_transports[key_transport].data_algorithms[data_alg]` using exact, case-sensitive algorithm URIs. A transport or data algorithm known elsewhere does not authorize this path, and legacy RSA transport or CBC content encryption is not implied by the recipient.

`key_size` is a JSON integer, not a numeric string or boolean, and must be an exact member of the selected data algorithm's `key_sizes`. The size is therefore bound to both data_alg and its parent transport rather than checked as an isolated positive number.

`reference_uri` is at most `reference_length_max` characters, matches `reference_pattern` as exactly one local fragment, and starts with one of the selected data algorithm's `reference_prefixes`. Do not decode or normalize a malformed URI into an accepted reference. Sign every field in order, enforce active-key HMAC and iat age/skew, and consume nonce only on allow; deny leaves store unchanged.
