# ebpfmap admit rules

## Signing input
`v1|{kid}|{map_id}|{key_hex}|{value_sha256}|{pin}|{iat}|{nonce}`

## Map bind
map_id ∈ maps; len(key_hex)==key_bytes*2 and hex; pin startswith maps[id].pin_prefix;
reject pin deny substrings; value_sha256 length; HMAC+revoke; time; nonce allow-only.
