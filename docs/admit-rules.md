# corpussel admit rules

Select `targets[target]`, then its `formats[format]`; a format valid for another target or another format of the same target is irrelevant. `input_sha256` is exactly `sha256_hex_len` lowercase hexadecimal characters, with no algorithm prefix or uppercase normalization.

`size` and `coverage_edges` are integers. Size is inclusive within the selected format's `size_min..size_max`; coverage is inclusive within its `coverage_min..coverage_max`. Additionally, `coverage_edges <= size * max_edges_per_byte` must hold using the parent target's density limit. Boundary values are allowed, values one beyond them are not.

`timeout_ms` must exactly occur in the selected format's `timeouts_ms`; do not accept an arbitrary positive duration. All numeric comparisons use integer values, not strings or booleans.

The signature covers digest, size, coverage, format and timeout in the declared order. Require active-key HMAC and valid iat age/skew, then consume nonce only for an allow. A denied seed never modifies store.
