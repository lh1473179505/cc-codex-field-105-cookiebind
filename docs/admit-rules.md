# sseauth admit rules

channel selects the complete SSE policy and user must be an exact member of that channel's users. origin is an exact scheme/host string without path, query, fragment or trailing slash; authorization on another channel or an Origin lookalike is irrelevant.

last_event_id is a non-empty resume cursor matching the channel's anchored ASCII pattern. Its decimal suffix is parsed as an integer and must lie within the inclusive numeric bounds. A cursor from another channel, shortened digits and zero are denied; no missing cursor is interpreted as an authorized resume.

event_types is an ordered array of unique exact strings, a subset of the channel event_types and a superset of required_event_types. No case folding or wildcard subscription is performed. Cursor, Origin and event order all enter HMAC with the other fields. Active key, 600-second iat age, 60-second future skew and fresh nonce are required. Only allow consumes nonce and saves store.
