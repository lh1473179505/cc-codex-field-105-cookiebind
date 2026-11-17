# zeeknotice admit rules

Select `notice_types[notice_type]`. `source_script` must be a relative slash-separated path ending in `script_suffix`, contain none of `script_deny_substrings`, have no empty/`.`/`..` component, and exactly match one of that notice's `source_scripts`. A script registered for another notice is not interchangeable.

`severity` and `action` must each belong to the selected notice's lists. `field_names` is a case-sensitive, unique string list with inclusive size `field_count_min..field_count_max`; it must be a subset of `fields_allowed` and contain every `fields_required` item. Empty lists and duplicate names are invalid rather than normalized.

The complete signing line preserves field order. Require a valid active-key HMAC and a fresh iat under the configured age/skew limits. Consume nonce only after all business gates allow; a deny must not save store.
