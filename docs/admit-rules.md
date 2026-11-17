# rolechain admit rules

Resolve source_role and then target_role only within that source's targets map. external_id must exactly match the selected edge. duration is an inclusive integer range on that edge. session_name must match session_pattern and start with an edge session_prefix; valid syntax cannot compensate for a cross-chain prefix.

When mfa_required is true, mfa must match mfa_pattern and start with the edge mfa_prefix. When it is false, mfa must be the empty string. Do not infer trust from a target role that exists under another source.

Verify HMAC over the exact `v1|` line in parts order. Enforce active keys, clock_skew_seconds/max_age_seconds and allow-only nonce consumption; every denial leaves store unchanged.
