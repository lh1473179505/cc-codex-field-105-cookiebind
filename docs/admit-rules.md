# dischargx admit rules

Offline macaroon-like capability with optional third-party discharge.
No network. HMAC-SHA256 chained signatures, base64url without `=`.

## Root chain

1. Start: `HMAC(root_key, ascii("v1|id|{identifier}"))`
2. For each caveat in array order: `HMAC(prev, caveat_line)`
3. Final digest base64url is `root.sig`

### Caveat lines (ASCII)

- `v1|time_before|{abs_unix}`
- `v1|exact_path|{path}`
- `v1|method_allow|{methods_csv}`  (CSV in JSON array order; do not sort)
- `v1|audience|{aud}`
- `v1|third_party|{location}|{predicate}|{ticket_hint}`

## Discharge chain

1. Start: `HMAC(discharge_key, ascii("v1|id|{identifier}|bind|{binds_root_sig}"))`
2. Chain caveat lines:
   - `v1|time_before|{abs_unix}`
   - `v1|predicate_satisfy|{predicate}`
3. Final digest base64url is `discharge.sig`

`binds_root_sig` must equal the verified `root.sig` tip (string equality).

## Request gates (all required for allow)

Bundle carries `request: {path, method, aud}` and optional `discharge`.

1. `root.kid` exists and status is not `revoked`; verify root HMAC chain.
   Revoked kid => `root_revoked` even if HMAC verifies with the revoked secret.
2. Evaluate first-party caveats against `request` and `now`:
   - `time_before`: `now <= abs_unix + clock_skew_seconds` else `root_expired`
   - `exact_path`: when `path_match=exact`, `request.path` must equal caveat path
     (prefix / suffix / normalized `..` tricks do not count)
   - `method_allow`: `request.method` must be in the list
   - `audience`: when `audience_match=exact`, equal strings only
3. If any `third_party` caveat exists:
   - `require_discharge_for_third_party`: missing discharge => `discharge_required`
   - discharge `location` must exactly equal the third_party `location`
     (`discharge_location_match=exact`) else `discharge_location`
   - verify discharge kid not revoked; verify discharge HMAC chain
   - `binds_root_sig` must equal root tip else `bind_mismatch`
   - discharge `time_before` vs now else `discharge_expired`
   - some `predicate_satisfy` caveat must exactly equal third_party `predicate`
     else `predicate_mismatch`
4. If no `third_party` caveat and `forbid_extra_discharge` and discharge present
   => `extra_discharge`
5. Nonce store: existing nonce => `replay`. Persist nonce **only** on allow.

## Exit codes
allow=0, deny=1, load failure=2
