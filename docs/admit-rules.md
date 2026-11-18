# perfevent admit rules

profile selects the complete perf-event policy. pid and cpu are JSON integers in their inclusive profile ranges; numeric strings and booleans are invalid. When system_wide is false, pid must be positive and the per-process profile cannot use the system-wide sentinel -1. When system_wide is true, the configured range must select exactly the approved system-wide PID/CPU combination.

event_type is an exact case-sensitive member of the profile list. sample_freq is an integer inside the inclusive profile sampling range. privileged is a JSON boolean exactly equal to the profile requirement, and paranoid is an integer in paranoid_values. A host-wide profile's event or privilege cannot be borrowed by a per-process request, and a permissive paranoid value cannot expand the PID/CPU scope.

Sign all fields in their declared order, including both selectors and the sampling frequency. Verify HMAC-SHA-256, active key status, iat freshness/skew and nonce uniqueness. Only a complete allow consumes nonce and saves store; every denial preserves prior state.
