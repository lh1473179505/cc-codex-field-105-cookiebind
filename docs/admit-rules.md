# amqppub admit rules

Traverse vhost -> user -> exchange. Do not accept a user or exchange merely because it exists in another vhost. routing_key must start with an exchange routing_prefix and contain no `*` or `#` wildcard. delivery_mode belongs to the exchange list.

Headers must be a subset of allowed_headers, include every required_headers key with its exact value, and contain no deny_headers key. Header names are lowercase and unique as JSON object keys. body_sha256 is exactly 64 lowercase hex. The signature sorts header keys and joins key=value with commas. Apply revocation/iat and nonce semantics without writing store for any deny.
