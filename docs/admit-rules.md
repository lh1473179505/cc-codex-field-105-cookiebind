# kafkacross admit rules

## Signing
`v1|{kid}|{principal}|{resource}|{name}|{op}|{group}|{client}|{host}|{pattern}|{iat}|{nonce}`

## Cross binds
principal ∈ principals. name rejects deny substrings; Topic name startswith topics[].
resource ∈ allowed_resources; op ∈ principals[p].ops; pattern ∈ principals[p].patterns.
client required for Write/Read and must ∈ clients[]; host must fall in hosts[] CIDRs (use ipaddress).
Read requires group startswith groups[].

HMAC+revoke; time; nonce allow-only. deny must not write store.
