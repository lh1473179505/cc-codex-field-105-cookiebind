# kanikox admit rules

Select `contexts[context]` by exact URI. The context must retain its canonical registered spelling; traversal, encoded path tricks and URI normalization cannot turn another directory into the selected context. `context_sha256` is exactly `sha256_hex_length` lowercase hexadecimal characters and equals that context's content digest.

`destination` must exactly equal the registered registry/repository/tag string for this context. A destination valid for another Kaniko context is denied. `cache` is a JSON boolean exactly equal to the context's cache flag. When true, `cache_repository` must exactly equal its configured non-empty repository; when false, it must be the empty string.

`certificate_path` is a canonical absolute path beneath `certificate_root`, exactly equal to the context's certificate file, with none of `path_deny_substrings` and no `.`/`..` component. Do not accept another CA merely because it is in the same directory.

Authenticate the complete context/digest/destination/cache/certificate tuple in declared order. Enforce active-key HMAC, iat age/skew and nonce replay checks. Only an allow consumes nonce and saves store; every deny leaves state untouched.
