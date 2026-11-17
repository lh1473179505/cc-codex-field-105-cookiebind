# pamstack admit rules

Select service and require order to be an integer index into its configured stack. The submitted module, control and complete arguments object must exactly equal the stack entry at that index; this binds position and prevents a later module from being substituted for an earlier required step. A module known in another service or at another position is invalid here.

module is a bare basename, not a path, and forbidden_modules are denied independently. Missing, additional or changed arguments are invalid. require_terminal_deny means every configured service stack must end in an exact required pam_deny.so entry; an entry cannot weaken or bypass that terminal contract.

Verify HMAC over the exact `v1|` line in parts order, sorting arguments as `key=value`. Enforce key status, clock_skew_seconds/max_age_seconds and allow-only nonce use. Denials leave store unchanged.
