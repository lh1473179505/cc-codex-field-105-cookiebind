# netnsacl admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{ns}|{ifaces_csv}|{forward}|{dns_csv}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- forward 必须 false
- dns 必须落在 allowed_dns_cidrs
- 接口名白名单
- kid 撤销

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-isolated, ok-dualstack

Deny cases: bad-sig, forward, dns, iface, revoked, empty-dns, v6-linklocal, route

Reason codes should be stable snake_case identifiers matching the failing gate.
