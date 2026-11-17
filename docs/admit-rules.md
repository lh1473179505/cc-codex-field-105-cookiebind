# polkitact admit rules

subject must match subject_pattern and occur in the selected action's subjects list. auth must contain exactly the action's three configured keys and exact values; allow_any=yes or an extra convenience key cannot widen authorization. annotations keys must be a subset of annotations_allowed and include every annotations_required key with its exact value.

session is exactly an object with type, active and local. type must belong to session_types, and active/local must equal the action's require_active/require_local values. Subject eligibility, authentication result and session state are conjunctive, not alternatives.

Verify HMAC over the exact `v1|` line in parts order, rendering auth, annotations and session with sorted `key=value` pairs. Enforce key status, clock_skew_seconds/max_age_seconds and allow-only nonce consumption. Denials leave store unchanged.
