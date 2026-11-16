# hstschain admit rules

## Signing input
`v1|{kid}|{host}|{max_age}|{include_sub}|{preload}|{report_uri}|{ct_log}|{iat}|{nonce}`

## Host normalize
Strip trailing `.` if host_normalize_strip_dot. If host_normalize_www and host startswith `www.`, map to apex for policy lookup using aliases tables (www.pay.example → pay.example). Host or its normalized form must match a hosts key or appear in some aliases list.

## HSTS / preload
max_age >= max_age_min. If require_sub: include_sub==1. If not allow_preload: preload==0.
If forbid_preload_without_sub and preload and not include_sub => deny.
If require_preload_if_listed and preload_listed: preload must be 1.

## report_uri
Parse URL. https only if forbid_http_report. No userinfo if forbid_userinfo_report.
hostname ∈ report_hosts for the resolved host policy. path must startswith report_path_prefix.

## CT
ct_log ∈ hosts[resolved].ct_logs.

HMAC + kid_revoked; time window; nonce store write only on allow.
