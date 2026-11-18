# hpkebind admit rules

Traverse `recipients[recipient].suites[kem]`; an unknown recipient or a KEM registered only for another recipient is invalid. `kdf` must exactly equal the selected KEM entry's KDF. Then select `aeads[aead]` beneath that same KEM rather than accepting a globally known AEAD.

`info` must exactly equal the selected AEAD entry's info string. `aad` is a printable ASCII string with inclusive length `aad_length_min..aad_length_max`, contains no control characters, and starts with one of that AEAD entry's `aad_prefixes`. Both info and AAD belong to the complete recipient/KEM/KDF/AEAD path; matching only one context field is insufficient.

Sign recipient, all three suite identifiers, info and AAD in the declared order. Enforce active-key HMAC and iat age/skew before allow-only nonce consumption. A denied encapsulation never writes store.
