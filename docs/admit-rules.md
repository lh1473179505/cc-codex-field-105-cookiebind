# mqttacl admit rules

## Signing input
`v1|{kid}|{client_id}|{topic}|{qos}|{payload_sha256}|{iat}|{nonce}`

## Gates
1. HMAC + kid_revoked.
2. topic must start with client_topic_prefix[client_id].
3. topic must not contain forbidden substrings.
4. qos <= max_qos.
5. iat age + nonce store allow-only.
