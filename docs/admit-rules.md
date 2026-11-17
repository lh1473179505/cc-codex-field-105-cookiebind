# attackmap admit rules

Select `rules[rule_id]` and require `technique_id` both to match `technique_pattern` and to exist in global `techniques`. The technique must also occur in the selected rule's `techniques`; global knowledge of a technique does not make it valid for every rule.

`tactic` must belong to `techniques[technique_id].tactics`. `data_source` must select a key beneath that same technique. `evidence_fields` is a unique, case-sensitive string list with inclusive size `evidence_count_min..evidence_count_max`, and every item must occur in `data_sources[data_source]` for the technique.

The evidence list must contain the rule's `required_evidence`. `confidence` is an integer in inclusive `confidence_min..confidence_max` for that rule. Whenever `confidence >= high_confidence_min`, every `high_confidence_evidence` item must also be present; a high score cannot compensate for missing corroboration.

Preserve evidence order in the signing line. Verify complete HMAC, active key and iat age/skew, and consume nonce only on allow. Denied mappings never write store.
