# pkcs11op admit rules

`slot` is a JSON integer, not a numeric string or boolean; its decimal spelling selects `slots[slot]`. `token` must exactly equal that slot's token, and `key_label` must select a key beneath that same slot/token pair. A label present in another HSM token grants no access here.

`mechanism` selects an entry beneath the selected key. `usage` must exactly belong to that mechanism's `usages`, so a signing key cannot be repurposed for decryption or wrapping. `pin_source` matches `pin_source_pattern`, is an indirect env/file/fd reference rather than a literal secret, and must exactly occur in the same mechanism entry's `pin_sources`.

Authenticate slot, token, key label, mechanism, usage and PIN source in the declared order. Require active-key HMAC and a fresh iat under the age/skew limits. Only a full allow consumes nonce or saves store; denial has no state side effects.
