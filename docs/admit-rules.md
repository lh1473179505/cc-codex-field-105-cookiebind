# symfetch admit rules

`symbol_server` must match `server_pattern` and exactly select `servers[symbol_server]`; HTTP, trailing-slash variants and unknown hosts are invalid. Traverse `builds[build_id].files[file_name]`, then require `arch` in that file's `arches`. `file_name` is one basename containing none of `file_deny_substrings`.

`file_sha256` is exactly `sha256_hex_len` lowercase hexadecimal characters and must equal the selected file entry's `sha256`. Matching digest syntax alone does not authorize a different build or file.

`path` must contain none of `path_deny_substrings` and must exactly equal `/{build_id}/{arch}/{file_name}` using the unmodified input fields. Do not decode, normalize, reorder or clean an unsafe path into this canonical form. Component count is therefore exactly three after the leading slash.

The signature covers server, build, file, architecture, digest and path. Require active-key HMAC and fresh iat under age/skew limits; consume nonce and save store only after allow.
