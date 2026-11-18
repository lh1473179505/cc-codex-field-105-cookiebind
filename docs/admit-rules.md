# lsmblob admit rules

object is an exact policy key including its object-kind prefix; no path normalization or object-kind coercion is permitted. label must be a complete case-sensitive member of that object's labels. blob_fields is a non-empty ordered list of unique field names, a subset of fields_allowed and a superset of fields_required for the same object. A field required on one object cannot be omitted because another object allows a smaller set.

operator must be an exact key beneath the selected object's operators map, and context must be a complete case-sensitive member of that operator's context list. Merely being a valid operator or security context elsewhere in policy is insufficient. Object, label, field set, operator and context therefore form one binding rather than five independent allowlists.

The signing line preserves blob_fields order and includes every identity and label field. Require valid HMAC-SHA-256, non-revoked key, iat within freshness/skew limits and an unused nonce. Consume nonce and persist store only after all gates allow; every denied blob update leaves existing state unchanged.
