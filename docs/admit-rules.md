# capbound admit rules

Capability set admission for a process profile. Lists joined in JSON array order.

## Signing

`v1|{kid}|{permitted_csv}|{effective_csv}|{bounding_csv}|{ambient_csv}|{no_new_privs_0_1}|{securebits}|{nonce}`

## Gates

1. HMAC + kid revoke.
2. No cap in denied_caps anywhere (permitted/effective/bounding/ambient).
3. All caps must be in allowed_caps union denied check already fails denied.
4. effective ⊆ permitted; permitted ⊆ bounding.
5. If forbid_ambient_unless_raiseable: ambient must be empty in fixtures unless policy later allows; nonempty ambient => `ambient_forbidden`.
6. require_no_new_privs => no_new_privs must be true.
7. securebits exact match one of allowed_securebits.
8. len(effective) <= max_effective.
9. nonce replay; write only allow.
