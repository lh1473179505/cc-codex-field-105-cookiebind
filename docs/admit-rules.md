# aptrepos admit rules

## Signing input
`v1|{kid}|{uri}|{suite}|{component}|{signed_by}|{arch}|{iat}|{nonce}`

## URI
Parse uri; scheme ∈ allowed_schemes; hostname ∈ allowed_hosts; reject uri_deny_substrings.
suite ∈ suites; component ∈ suites[suite]; signed_by ∈ signed_by_allow; arch ∈ arch_allow;
HMAC+revoke; time; nonce allow-only.
