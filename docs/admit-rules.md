# mqauthz admit rules

## Signing input
`v1|{kid}|{client_id}|{cn}|{topic}|{qos}|{retain_0_1}|{payload_sha256}|{payload_len}|{iat}|{nonce}`

## MQTT ACL match (policy filter vs publish topic)
Policy filters may contain `+` / `#`. Publish topic MUST NOT contain wildcards if forbid_publish_wildcards.
Match rules (standard MQTT):
- filter segment `+` matches exactly one topic segment
- filter `#` matches remaining segments (must be last)
Topic matches client_acl[client_id] if ANY filter matches.

## Gates
1. HMAC + kid_revoked.
2. cn must regex-match cn_patterns[client_id].
3. topic ACL match; reject publish wildcards; reject `$share/` and `$SYS/` prefixes when forbidden.
4. qos <= max_qos; if retain and retain_forces_qos0 => qos must be 0; retain only if topic starts with retain_allow_prefixes.
5. payload_len <= max_payload_bytes.
6. time + nonce store allow-only.

## Compatibility
inspect stays echo-only; deny does not write store.
