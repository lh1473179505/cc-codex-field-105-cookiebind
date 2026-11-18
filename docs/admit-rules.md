# nixstore admit rules

Select `paths[store_path]` by exact string. The path must start with `store_prefix`, contain a 32-character store hash followed by a hyphen and registered name, and contain none of `path_deny_substrings` or `.`/`..` path components. Registration is exact: never normalize traversal or accept an unregistered path with plausible Nix syntax.

`nar_hash` is exactly `nar_hash_prefix` followed by `nar_hex_length` lowercase hexadecimal characters and equals the selected path's NAR digest. `size` is a JSON integer exactly equal to the registered byte size, not a numeric string or boolean. A valid hash or size belonging to another path is invalid.

`signature` must exactly equal the signature assigned to this store path, including key name and encoded payload; a trusted signature assigned to another path is not sufficient. `references` is an ordered, unique list exactly equal to the path's registered list, every item must occur in `reference_registry`, and self-reference is forbidden even when the expected list is empty.

The signing line preserves reference order and covers store path, NAR hash, size and signature. Verify active-key HMAC, iat freshness/skew and unused nonce before consuming nonce or saving store on allow. Every deny leaves store unchanged.
