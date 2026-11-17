# crashdump admit rules

Traverse `products[product].builds[build_id].arches[arch]`. Product, build and architecture must all belong to one path; a build ID or architecture known elsewhere is invalid.

`pc_address` is exactly `0x` followed by `pc_hex_digits` lowercase hexadecimal digits. Parse it as an unsigned address. `module_offset` is an integer in `0 <= module_offset < module_size`, and the numeric PC must equal `module_base + module_offset` exactly. A syntactically valid PC at another offset is not accepted.

`dump_sha256` is exactly `sha256_hex_len` lowercase hexadecimal characters. `size_bytes` is an integer in the selected build's inclusive `dump_size_min..dump_size_max`; limits are build-specific rather than product-wide.

Include both address representations, digest and size in the signed line. Enforce key status, iat freshness/skew and replay protection. Only a full allow may consume nonce or save store.
