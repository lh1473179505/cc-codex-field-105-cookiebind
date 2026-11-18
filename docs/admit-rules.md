# cvssvec admit rules

`version` must belong to `versions` and exactly equal the selected vector registration's version. `vector` must be an exact key in `vectors`, including the `CVSS:` prefix, version-specific metric names and canonical order. Reordering valid metrics or registering an unlisted vector is invalid.

`metrics` is an object with exactly the selected vector's `metric_keys`, and every value must exactly equal its registered value. Reconstruct the canonical vector as `CVSS:{version}` followed by slash-separated `key=value` pairs in `metric_keys` order and require equality with the original vector. Missing, extra or cross-version metrics are denied.

`score` is a JSON number, not a boolean or numeric string, in 0.0..10.0 with at most one decimal place, and exactly equals the registered base score. `severity` must equal both the registered severity and the unique `severity_ranges` bucket containing that score. Do not replace the base score with an environmental score.

`environmental` is an object whose keys are a subset of the selected vector's `environmental_allowed` and which contains every `environmental_required` key/value exactly. Values belong to `environmental_values`; an empty object is valid only when no environmental metric is required. Unknown supplemental or modified-base metrics cannot be smuggled into this object.

Serialize metrics and environmental objects in their specified key orders for HMAC, retaining vector and numeric score exactly. Enforce active-key status, iat age/skew and replay protection. Only allow consumes nonce or writes store.
