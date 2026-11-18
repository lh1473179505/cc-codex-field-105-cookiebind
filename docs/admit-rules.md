# nucleix admit rules

`template_id` must match `template_id_pattern` and select one template. `protocol` must exactly equal that template's protocol; HTTP behavior cannot be inferred for DNS or vice versa.

`matcher` has exactly `matcher_keys` and must equal one complete object in `matchers_allowed`, including ordered words and condition. `extractor` has exactly `extractor_keys` and must equal one complete object in `extractors_allowed`, including ordered regexes and integer capture group. Removing a required word, changing AND to OR, or selecting group zero is invalid.

`request_headers` is an object with string values and no duplicate names after ASCII lowercase conversion. Header names are compared case-insensitively for both allowed and forbidden checks. Every lowercase name must occur in the template's lowercase `headers_allowed`, and no name may occur in `forbidden_headers`. Every `headers_required` name/value pair must be present exactly. For non-HTTP templates, the header object must be empty; dangerous-hop, credential and host-override headers are never excused by a valid matcher.

Serialize matcher and extractor with sorted object keys while preserving nested array order; do the same for headers after retaining their original names. Enforce full HMAC, active key, iat age/skew and allow-only nonce consumption. Deny never writes store.
