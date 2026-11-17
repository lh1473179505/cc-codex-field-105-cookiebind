# crlissue admit rules

issuer selects one issuer policy. signature_alg is an exact case-sensitive member of that issuer's list. crl_number is a JSON integer inside the inclusive issuer-specific minimum and maximum; numeric strings and booleans are not integers for this contract.

this_update and next_update are canonical UTC strings in YYYY-MM-DDTHH:MM:SSZ form, without offsets or fractional seconds. next_update is strictly later than this_update and their difference is exactly the issuer validity_seconds.

reasons is a string array containing only the issuer's reasons_allowed, with no duplicates and at most max_reasons entries. The signed line preserves reasons order and covers every business field. Active HMAC keys, iat freshness/skew and unused nonce are required for allow. Denials do not mutate store.
