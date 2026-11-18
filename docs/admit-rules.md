# scimprov admit rules

Traverse tenant -> resource_type. external_id has the tenant/type prefix and minimum length. operation must be allowed for that type. attributes are a bounded object with only attribute_allow keys, all required keys present, and nonempty scalar string values. bulk_id starts with the tenant prefix. Permissions from another resource type or tenant do not carry over.

Verify HMAC-SHA-256 over the exact signing line in the documented field order. Reject unknown/revoked keys and stale or future iat values. A nonce is consumed only after every gate allows; every deny leaves store unchanged.
