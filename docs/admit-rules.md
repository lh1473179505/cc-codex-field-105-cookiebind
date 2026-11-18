# dsseenv admit rules

Select `payload_types[payloadType]` with an exact, case-sensitive media type. `payload_sha256` is exactly `payload_hex_length` lowercase hexadecimal characters and equals the digest registered for that payload type; a digest belonging to another DSSE type is invalid.

`signatures` is an ordered list of at most `signature_count_max` objects, each having exactly `signature_keys`. Every signer must be unique and must occur in the selected payload type's `signers`; its paired `keyid` must occur in that signer's own list. A keyid assigned to amy does not authenticate alice, and duplicate signatures from one signer count only as a denial, not as threshold progress.

`threshold` is an integer exactly equal to the selected payload type's threshold, and the number of distinct valid signer entries must be at least that threshold. Serialize each signature as `signer:keyid` in list order for the complete HMAC line. Enforce active-key HMAC and iat age/skew, and consume the outer nonce only on allow; deny never writes store.
