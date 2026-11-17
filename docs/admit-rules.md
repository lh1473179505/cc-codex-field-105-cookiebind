# kmodsig admit rules

module matches `[a-z][a-z0-9_-]*` and selects policy.modules[module]. path is an absolute canonical path with no path_deny_substrings or empty/`.`/`..` component and exactly equals the module path. digest is exactly digest_hex_len lowercase hexadecimal characters and equals the configured module digest; valid syntax alone is insufficient.

sig_alg belongs to the selected module's sig_algs and keyring equals its keyring. params is an object with string values, keys restricted to params_allowed, every params_required key/value present exactly, and each supplied value in the corresponding param_values list. Sorting params keys in the signing line does not relax the key set. Verify complete HMAC, active key and iat window; consume nonce only on allow and never write store on deny.
