# filecaps admit rules

path is an absolute canonical slash-separated executable path and an exact key in paths. Repeated slashes, empty components, backslashes, NUL and `.`/`..` components are invalid; normalization must not turn an unregistered path into an allowed one. The selected path supplies all capability limits.

capabilities is a non-empty unique list of lowercase `cap_` names, a subset of capabilities_allowed and a superset of capabilities_required. permitted is a unique list with exactly the same membership as capabilities, although its supplied order remains significant for signing. effective is non-empty and unique, and must be a subset of both permitted and the path's effective_allowed. A capability valid on another path grants nothing here.

bounding is a unique subset of capabilities, contains every bounding_required item and contains no global bounding_forbidden item. The four lists are signed in their supplied order without sorting or deduplication. Verify HMAC-SHA-256, active-key status, iat freshness/skew and unused nonce before allow; only allow consumes nonce or changes store.
