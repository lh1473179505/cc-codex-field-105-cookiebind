# wsshand admit rules

host and exact path jointly select the configured `wss://host/path` endpoint. Host comparison is exact and lowercase; an explicit port is not silently discarded. path excludes query strings, fragments, repeated separators and traversal rather than being normalized. origin must exactly equal an allowed scheme/host origin with no path or trailing slash.

subprotocol is one exact member of the selected endpoint's protocols. websocket_key is canonical base64 decoded with validation to exactly 16 bytes; arbitrary text and short decoded values are invalid. extensions is an ordered array of unique extension tokens that must exactly equal one configured extension_sets entry, including the empty-list case. Parameters and unregistered extensions are not ignored.

The original host, path, origin, key and extension order enter HMAC with all fields. Verification requires an active key, iat age at most 600 seconds and future skew at most 60 seconds, and a fresh nonce. Only allow consumes nonce and persists store.
