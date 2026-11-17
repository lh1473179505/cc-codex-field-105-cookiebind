# sigmarule admit rules

Select `rules[rule_id]`; an unknown rule ID is invalid. `title` must exactly equal the registered title and its length must not exceed `title_length_max`. `logsource` is an object with exactly `logsource_keys`, and both values must equal the selected rule's logsource; do not merge logsources across rules.

`detection` is a unique string list with inclusive size `detection_count_min..detection_count_max`. It must be a subset of `detection_allowed` and contain every `detection_required` item. For every selected selector, all fields at `selector_fields[selector]` must occur in `field_names`.

`field_names` is a unique, case-sensitive string list with inclusive size `field_count_min..field_count_max`; it must be a subset of `fields_allowed` and contain `fields_required`. `level` must belong to the selected rule's `levels`. Membership under another rule never satisfies these contracts.

The signing line preserves list order and serializes logsource as sorted `key=value` pairs. Verify the active-key HMAC, enforce the iat age/skew window, and consume nonce only on allow. Every deny leaves store unchanged.
