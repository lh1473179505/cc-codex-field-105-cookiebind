# idnapin admit rules

Offline URL authority pinning for egress. No real DNS/network.

## Signing input

`v1|{kid}|{method}|{url}|{body_sha256}|{authority_host}|{pin_ips_csv}`

HMAC-SHA256 over the UTF-8 bytes of that line, then base64url without `=`. `url` / `authority_host` are the **raw** plan strings (do not normalize / IDNA-convert before verifying the signature).

## Parsing rules

1. Scheme must be in `allowed_schemes` (https only in fixtures).
2. If `forbid_userinfo` and userinfo present => `userinfo_forbidden`.
3. If `forbid_http_backslash` and the raw URL contains `\` before the path query fragment handling completes in a way that can confuse authority (fixture `deny-backslash`) => `bad_authority`.
4. Host allow uses **exact** match against a normalized host:
   - ASCII hosts: lowercase
   - Non-ASCII Unicode hosts are **not** auto-allowed via U-label; when `idna_policy=prefer_punycode_label`, only the punycode `xn--` form listed in `host_allow` passes. Unicode form => `idna_required`.
5. If host is dotted-decimal / integer IPv4 obfuscation (`forbid_decimal_ipv4_obfuscation`) such as `3232235777` => `ipv4_obfuscation` (do not connect).
6. Resolve host only via plan `resolver` map; missing => `nxdomain`.
7. Every resolved IP must be listed in `pin_ips` (`pin_mismatch` otherwise). Any IP in `blocked_cidrs` => `blocked_ip` even if pinned.
8. Method allowlist.
9. kid revoked => `kid_revoked` even if HMAC ok.
10. Redirects (if present): each Location raw string re-runs gates; max_redirects.

## Exit codes
allow=0 deny=1 loadfail=2
