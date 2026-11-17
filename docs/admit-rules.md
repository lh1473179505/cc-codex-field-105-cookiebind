# kafkacross admit rules

## Signing
`v1|{kid}|{principal}|{resource}|{name}|{op}|{group}|{client}|{host}|{pattern}|{iat}|{nonce}`

## Cross binds
principal ∈ principals. name rejects deny substrings; Topic name startswith topics[].
resource ∈ allowed_resources; op ∈ principals[p].ops; pattern ∈ principals[p].patterns.
client required for Write/Read and must ∈ clients[]; host must fall in hosts[] CIDRs (use ipaddress).
Read requires group startswith groups[].

HMAC+revoke; time; nonce allow-only. deny must not write store.

## Signing line and signature
Key is `keys[kid].secret` hex-decoded to raw bytes. HMAC-SHA256 over the
signing line, base64url without padding, compared with `hmac.compare_digest`.

## Time window
`now - max_age_seconds <= iat <= now + clock_skew_seconds`.

## Nonce / store
`store.items` maps nonce to `{"ts": iat}`. An existing nonce is a replay deny.
The nonce is inserted only when the final decision is allow; deny never mutates
the store, and the CLI saves the store only after an allow decision.

## Reason codes
Collected in evaluation order; any non-empty list means deny:

- `key_unknown`, `key_revoked`, `bad_signature`
- `iat_invalid`, `time_expired`, `time_future`
- `principal_denied`, `resource_denied`, `name_invalid`, `name_deny_substring`
- `topic_prefix_denied` (Topic only), `op_denied`, `pattern_denied`
- `client_denied` (ops in `client_required_for`), `host_denied` (`ipaddress` CIDR)
- `group_denied` (ops in `group_required_for`, must start with a groups prefix)
- `nonce_invalid`, `nonce_replay`
