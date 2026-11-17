# sudorun admit rules

Select user, then require group and host in that user's lists before selecting command beneath the same user. command must be a canonical absolute path with no empty, `.` or `..` component, backslash or NUL; do not resolve traversal to an allowed executable. The selected command additionally constrains group and host, so user-level membership alone is insufficient.

args_sha256 must be exactly 64 lowercase hex characters and equal the digest configured for that user/command. noexec must equal require_noexec. A digest from another command or user is invalid.

Verify HMAC over the exact `v1|` line in parts order. Enforce active keys, clock_skew_seconds/max_age_seconds and allow-only nonce consumption. Denials leave store unchanged.
