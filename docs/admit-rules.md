# hookdeliv admit rules

## Signing input
`v1|{kid}|{url}|{host}|{method}|{body_sha256}|{event}|{iat}|{nonce}`

## URL normalize
Parse URL; scheme ∈ allowed_schemes; hostname must equal host field and ∈ allowed_hosts.
Reject userinfo / query / fragment when corresponding forbid_* true.
Path must start with path_allow_prefixes; reject `..` / `//` in path.

## Gates
method/event allowlists; body_sha256 length; HMAC+revoke; time; nonce allow-only.
