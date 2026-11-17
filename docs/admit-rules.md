# usernsmap admit rules

parent_ns must exactly select a configured canonical `/proc/<pid>/ns/user` path; reject traversal, symlink-like aliases and normalization-based matching. container_uid and container_gid are integers within their respective inclusive parent ranges. length is an integer within length_min/length_max.

The half-open host intervals `[host_uid_start,host_uid_start+length)` and `[host_gid_start,host_gid_start+length)` must each be wholly contained in one same-type configured range. Starting inside a range is insufficient when the end overflows. When require_distinct_uid_gid_ranges is true, UID and GID host intervals must not overlap. newuidmap must exactly match the configured uid/gid helper-path object.

Verify HMAC over the exact `v1|` line in parts order, sorting newuidmap keys as `key=value`. Enforce active keys, clock_skew_seconds/max_age_seconds and nonce consumption only on allow. Denials leave store unchanged.
