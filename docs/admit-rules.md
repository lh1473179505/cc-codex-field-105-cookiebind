# corelimit admit rules

process selects one complete core-dump policy. sensitive is a JSON boolean that must equal the registered classification. If dumps_allowed is false, the request is denied regardless of otherwise well-formed storage settings; a caller cannot make a sensitive process eligible by changing its sensitive flag, owner or path.

core_path is a canonical absolute directory and must exactly equal the process path. Reject traversal, empty components, repeated slashes, backslashes and NUL instead of normalizing them. size_bytes is a JSON integer, excluding booleans and numeric strings, within the process's inclusive size_min/size_max range.

compression is an exact case-sensitive member of that process's compressions and owner exactly equals the configured non-world-writable service account. No setting may be borrowed from another process. The HMAC covers every field in order. Apply key revocation, iat freshness/skew and nonce replay checks, consuming nonce and saving store only for allow.
