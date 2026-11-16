# tlstickt admit rules

SNI selects all version, cipher, ALPN, early-data and lifetime limits. alpn must be unique, contain alpn_required and be a subset of alpn_allowed. Early data requires version TLS1.3 and an SNI with early_allowed. When early_data is 1, max_early is in [1,max_early_limit]; when early_data is 0 or early data is disallowed, max_early must be zero.

lifetime is inclusive within the SNI range. Do not infer validity from a cipher or version allowed for another SNI. HMAC covers the complete line; key status, iat window and replay state are enforced consistently by CLI and library, with no store write on deny.
