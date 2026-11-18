# cmsenv admit rules

Select `recipients[recipient]`. `key_alg` must exactly equal that recipient's key-management algorithm; an algorithm assigned to another recipient or an unsafe legacy algorithm is invalid. `content_enc` then selects an entry in that recipient's `content_encryptions`, so content-cipher membership is recipient-specific.

`digest_alg` must belong to the selected content encryption entry's `digest_algs`. `aad` is non-empty printable ASCII, no longer than `aad_length_max`, and starts with one `aad_prefixes` item from that same entry. Neither digest nor AAD may be borrowed from a different content cipher or recipient even when their string syntax is valid.

Authenticate recipient, key algorithm, content encryption, AAD and digest in the declared order. Check active HMAC key status, iat age/skew and replay state independently. Nonce and store are written only after a complete allow.
