# tuftarget admit rules

Select `repositories[repository].targets[target_path]` using the exact repository and target path. `target_path` is a relative canonical slash-separated path with no empty, `.` or `..` component and none of `path_deny_substrings`. Never clean traversal into a registered path; a path from another repository is not valid here.

`length` is a JSON integer exactly equal to the registered byte length. `hashes` is an object with exactly `hash_keys`, no missing or additional algorithms. Its `sha256` and `sha512` values are respectively exactly `sha256_hex_length` and `sha512_hex_length` lowercase hexadecimal characters and exactly equal the selected target's two registered digests.

`role` and `delegation` are case-sensitive strings that must both exactly equal the values attached to that same target. A trusted role or delegation used by another repository or target does not satisfy this pair; do not validate them as independent global allowlists.

Serialize hashes as sorted `algorithm=digest` pairs in the signing line and include path, length, role and delegation. Enforce active-key HMAC, iat age/skew and replay state before allow-only nonce/store mutation. Every denial leaves store unchanged.
