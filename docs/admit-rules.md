# eventarc admit rules

subscription selects one complete event-routing policy. source, event_type and handler must exactly equal or belong to that subscription's configured values; event type version suffixes are significant. A valid handler or event source from another subscription does not establish authorization here.

subject_prefix must exactly equal one configured absolute prefix, including its leading and trailing slash. It is a routing prefix declaration rather than a glob: empty components, dot-dot traversal, query/fragment delimiters and NUL are denied. No case folding, path cleaning or implicit wildcard is applied.

retry and deadletter are exact JSON objects. Retry integer values and all keys must match, and dead-letter topic and enabled state must match without borrowing another subscription's destination. Every nested value is signed in declared field order. Active HMAC keys, iat within 600 seconds plus 60 seconds of future skew, and unused nonce are required. Denial leaves store unchanged.
