# radcoa admit rules

The input is one JSON object. nas_id selects one NAS and username is then resolved only beneath that NAS. session_id contains only lowercase ASCII letters, digits and hyphens and starts with a NAS session_prefix. acct_session_id starts with a prefix bound to the selected NAS/user pair; a prefix from another user is invalid.

attributes is a JSON object whose values are strings. Its keys are a subset of attributes_allowed, every attributes_required key is present with its exact value, and every supplied key/value pair occurs in attribute_values. source_ip is parsed by `ipaddress.ip_address` and must be contained in a source_cidrs network of the same NAS.

The HMAC line covers fields in the declared order. Attribute keys are sorted and rendered as comma-separated key=value items. Unknown or revoked keys, stale/future iat and replayed nonces are denied. A denial leaves store unchanged.
