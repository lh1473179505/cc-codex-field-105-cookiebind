# proxyacl admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{user}|{method}|{host}|{port}|{iat}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- method GET/POST 或 CONNECT；CONNECT 端口必须在 connect_ports
- host 后缀匹配 allow_hosts
- user 身份；时间窗；kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-get, ok-connect

Deny cases: bad-sig, method, connect-port, host, user, revoked, skew, ip-literal

Reason codes should be stable snake_case identifiers matching the failing gate.
