# suricatax admit rules

## Signing
`v1|{kid}|{sid}|{proto}|{msg}|{content}|{iat}|{nonce}`

sid must fall in one sid_ranges inclusive; proto allow; msg startswith msg_prefixes; content len<=max and no deny substrings; HMAC+revoke; time; nonce allow-only.
