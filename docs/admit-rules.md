# tickpac admit rules

A service ticket carries an embedded PAC. Both layers are HMAC-SHA256
over fixed-order ASCII lines, then base64url without `=` padding.

## Ticket signing input

`v1|{ticket_kid}|{realm}|{cname}|{spn}|{authtime}|{starttime}|{endtime}|{renew_till}|{renewable_0_or_1}|{transited}|{pac_sha256}`

`pac_sha256` is SHA-256 hex of the PAC JSON object serialized with
`sort_keys=True` and separators `(',', ':')` **including** the PAC `sig`
field. Do not pretty-print.

## PAC signing input

`v1|{pac_kid}|{logon_domain}|{account}|{group_sids_csv}|{deny_sids_csv}|{logon_time}|{password_last_set}`

Group/deny SID lists are joined with commas in the array order present
in JSON (do not sort).

## Gates (all must hold for allow)

1. Ticket `ticket_kid` exists and is not revoked; verify ticket HMAC with ticket key.
2. Recompute PAC JSON digest; must equal `pac_sha256`. Then verify PAC HMAC with pac key; revoked pac kid => `pac_revoked` even if HMAC verifies.
3. If `require_pac_account_match`, PAC `account` must equal ticket `cname`.
4. Realm in `allowed_realms`. Transited path is comma-separated realms; hop count is number of commas+1 if non-empty. Must be `<= max_transit_hops`. If `require_contiguous_transit`, every hop must be in `allowed_realms` and the final hop must equal ticket `realm` (ticket realm alone with empty/self transit is ok when `transited == realm`).
5. SPN allow is **per realm**: `exact` or literal `prefix`. Do not treat allow entries as substrings of arbitrary SPNs (`http/evil.notapp.corp.example` must fail corp exact `http/app.corp.example`).
6. Group SIDs ∩ `allowed_group_sids` must be non-empty. Any SID in PAC `deny_sids` that appears in `denied_group_sids` => `sid_denied` (deny wins even if allow groups also present).
7. Time: `starttime - skew <= now <= endtime + skew`. `renew_till` is **not** an extension of `endtime` for admission of a non-renew request; `forbid_renewable_past_end` means renewable=true still cannot use renew_till to pass an expired endtime.
8. Nonce store: existing nonce => `replay`. Write nonce only on allow.

## Exit codes
allow=0, deny=1, load failure=2
