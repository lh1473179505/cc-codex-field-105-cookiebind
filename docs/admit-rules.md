# snmptrap admit rules

engine_id is exactly engine_id_hex_len lowercase hexadecimal characters and selects an engine. user must exist under that engine. auth and priv must be allowed for that user; require_authPriv forbids `none` or missing privacy even when authentication is valid.

The trap oid must start with an OID prefix configured for that engine/user. Numeric dotted OIDs contain no empty, leading-zero, signed or non-numeric components. Every varbind is a valid OID under varbind_prefix and under the same enterprise prefix as the trap oid. Enforce inclusive varbind count and severity membership. HMAC, revocation, iat and nonce rules apply to the entire object; deny never writes store.
