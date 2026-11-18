# hkdfkey admit rules

Select `profiles[profile]`; every derivation parameter is resolved beneath that one profile. `purpose` must equal the profile purpose exactly. `ikm_sha256` is exactly `ikm_hex_length` lowercase hexadecimal characters and equals the registered IKM digest, while `salt_hex` is exactly `salt_hex_length` lowercase hexadecimal characters and equals that same profile's salt.

`info` is a printable ASCII string no longer than `info_length_max` and must exactly equal one of the profile's `info_values`. `algorithm` selects a key in `algorithm_outputs`, and the integer `output_length` must be an exact member of the list beneath that algorithm. A digest, salt, info string, algorithm or output size valid for another profile never satisfies the selected profile.

The HMAC line covers purpose, both hex strings, info, output length and algorithm in the declared order. Require an active signing key and an iat within the configured age/skew window. Consume nonce only on allow; every denial leaves store unchanged.
