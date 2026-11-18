# spnegox admit rules

realm selects service, host suffix, mechanism and address policy. spn has exactly service/host@REALM form and its realm is identical to the top-level field. mech_types are unique, include required values and are a subset of allowed values. mutual must be enabled. address parses as IP and belongs to a realm CIDR. No case folding or canonicalization may erase a realm mismatch.

Verify HMAC-SHA-256 over the exact signing line in the documented field order. Reject unknown/revoked keys and stale or future iat values. A nonce is consumed only after every gate allows; every deny leaves store unchanged.
