# inotifyx admit rules

root and path are canonical absolute slash-separated paths. root must exactly select a roots entry, path must be strictly beneath that same root, and its first relative component must be in path_components. Deny root-only lookalikes, repeated separators, empty components, backslashes, NUL and all `.`/`..` traversal before considering any watch option.

event_mask is a non-empty ordered list of unique strings, a subset of the selected root's events_allowed and a superset of events_required. recursive is a JSON boolean exactly equal to the root requirement; integer zero and one are invalid. max_watches is a JSON integer, not a string or boolean, inside the inclusive watches_min/watches_max budget for that root.

The event list remains in supplied order for HMAC signing, while authorization applies the set and uniqueness rules above. Verify all fields, active key status, iat freshness/skew and unused nonce before allow. A denial must neither consume nonce nor save store, including failures discovered after path validation.
